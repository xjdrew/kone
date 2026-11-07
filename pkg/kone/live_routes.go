package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"
)

// captureRoutes describes only explicit routes; interface-connected Fake-IP
// routes remain owned by Configure. Sorting makes updates deterministic.
func captureRoutes(cfg CoreConfig, rule *Rule) []string {
	seen := map[string]bool{}
	add := func(prefix string) { seen[prefix] = true }
	if cfg.AutoRoute {
		add("0.0.0.0/1")
		add("128.0.0.0/1")
	}
	if cfg.AutoRoute6 {
		add("::/1")
		add("8000::/1")
	}
	for _, pattern := range rule.patterns {
		p, ok := pattern.(IPCIDRPattern)
		if !ok || rule.OutboundType(p.Proxy()) == OutboundDirect {
			continue
		}
		if p.prefix.Addr().Is6() && cfg.IPv6Network == "" {
			continue
		}
		if p.prefix.Bits() == 0 {
			if p.prefix.Addr().Is4() {
				add("0.0.0.0/1")
				add("128.0.0.0/1")
			} else {
				add("::/1")
				add("8000::/1")
			}
		} else {
			add(p.prefix.String())
		}
	}
	result := make([]string, 0, len(seen))
	for prefix := range seen {
		result = append(result, prefix)
	}
	slices.Sort(result)
	return result
}

func (one *One) restoreCaptureRoutes(ctx context.Context) error {
	var errs []error
	keys := sortedRouteKeys(one.captureRoutes)
	slices.Reverse(keys)
	for _, prefix := range keys {
		if undo := one.captureRoutes[prefix]; undo != nil {
			errs = append(errs, undo(ctx))
		}
	}
	one.captureRoutes = nil
	errs = append(errs, one.routeRemainders.restore(ctx))
	return errors.Join(errs...)
}

func sortedRouteKeys(routes map[string]Cleanup) []string {
	keys := make([]string, 0, len(routes))
	for key := range routes {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// Caller serializes this transaction with reload and shutdown. Publish the
// policy only after every route succeeds. Failed rollback stops the engine so
// it cannot continue reporting the old policy with a different capture scope.
func (one *One) updateCaptureRoutes(ctx context.Context, wanted []string) error {
	desired := map[string]bool{}
	for _, prefix := range wanted {
		desired[prefix] = true
	}
	var added, removed []string
	rollback := func(cause error) error {
		recovery, cancel := context.WithTimeout(context.Background(), one.shutdownTimeout)
		defer cancel()
		var errs []error
		for _, prefix := range removed {
			_, subnet, _ := net.ParseCIDR(prefix)
			undo, err := one.network.AddRoute(recovery, one.routeDevice, subnet)
			if err != nil {
				one.routeRemainders.add(prefix, undo)
				errs = append(errs, err)
			} else {
				one.captureRoutes[prefix] = undo
			}
		}
		for i := len(added) - 1; i >= 0; i-- {
			prefix := added[i]
			var err error
			if undo := one.captureRoutes[prefix]; undo != nil {
				err = undo(recovery)
			}
			if err != nil {
				errs = append(errs, err)
			} else {
				delete(one.captureRoutes, prefix)
			}
		}
		if err := errors.Join(errs...); err != nil {
			one.mu.Lock()
			if one.cancel != nil {
				one.cancel()
			}
			one.mu.Unlock()
			return errors.Join(cause, fmt.Errorf("route rollback failed; proxy stopped: %w", err))
		}
		return cause
	}
	for _, prefix := range wanted {
		if _, exists := one.captureRoutes[prefix]; exists {
			continue
		}
		_, subnet, _ := net.ParseCIDR(prefix)
		undo, err := one.network.AddRoute(ctx, one.routeDevice, subnet)
		if undo != nil || err == nil {
			one.captureRoutes[prefix] = undo
			added = append(added, prefix)
		}
		if err != nil {
			return rollback(fmt.Errorf("add route %s: %w", prefix, err))
		}
	}
	for _, prefix := range sortedRouteKeys(one.captureRoutes) {
		if desired[prefix] || one.routeReferences[prefix] > 0 {
			continue
		}
		if undo := one.captureRoutes[prefix]; undo != nil {
			if err := undo(ctx); err != nil {
				return rollback(fmt.Errorf("remove route %s: %w", prefix, err))
			}
		}
		delete(one.captureRoutes, prefix)
		removed = append(removed, prefix)
	}
	return nil
}

func (one *One) reloadCaptureRoutes(cfg CoreConfig, rule *Rule) error {
	one.mu.Lock()
	started, runContext := one.started, one.runContext
	one.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-one.ready:
	default:
		return errors.New("proxy is still starting; retry after startup")
	}
	ctx, cancel := context.WithTimeout(runContext, 15*time.Second)
	defer cancel()
	return one.updateCaptureRoutes(ctx, captureRoutes(cfg, rule))
}

// Pin the routes used by admitted connections until their sockets close. Policy
// changes apply immediately to new connections without stranding old sockets.
func (one *One) flowSnapshot(destination netip.Addr) (*runtimeSnapshot, func()) {
	one.reloadMu.Lock()
	snapshot := one.policy.Load()
	one.mu.Lock()
	started, closed, runContext := one.started, one.closed, one.runContext
	one.mu.Unlock()
	var pinned []string
	ready := false
	select {
	case <-one.ready:
		ready = true
	default:
	}
	if started && !ready && !closed {
		// Routes are installed after the stack starts. Admission must wait for
		// their complete ownership set; cancellation also releases callbacks
		// when startup fails before Ready can close.
		one.reloadMu.Unlock()
		select {
		case <-one.ready:
			return one.flowSnapshot(destination)
		case <-runContext.Done():
			return snapshot, func() {}
		}
	}
	if started && ready && !closed && destination.IsValid() {
		if one.routeReferences == nil {
			one.routeReferences = map[string]int{}
		}
		for prefix := range one.captureRoutes {
			if netip.MustParsePrefix(prefix).Contains(destination.Unmap()) {
				one.routeReferences[prefix]++
				pinned = append(pinned, prefix)
			}
		}
	}
	one.reloadMu.Unlock()
	return snapshot, func() {
		if len(pinned) == 0 {
			return
		}
		one.reloadMu.Lock()
		defer one.reloadMu.Unlock()
		one.mu.Lock()
		closed := one.closed
		one.mu.Unlock()
		if closed {
			return
		}
		for _, prefix := range pinned {
			one.routeReferences[prefix]--
			if one.routeReferences[prefix] == 0 {
				delete(one.routeReferences, prefix)
			}
		}
		current := one.policy.Load()
		if err := one.reloadCaptureRoutes(current.cfg.Core, current.rule); err != nil {
			// Preserve failed cleanup ownership until shutdown retries it.
			one.mu.Lock()
			if one.cancel != nil {
				one.cancel()
			}
			one.mu.Unlock()
		}
	}
}

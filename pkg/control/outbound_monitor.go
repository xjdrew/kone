package control

import (
	"context"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
)

func (c *Controller) wakeOutboundMonitor() {
	select {
	case c.healthWake <- struct{}{}:
	default:
	}
}

// One background probe at a time leaves capacity for interactive diagnostics.
// Only configured endpoints and the explicit check target are used. No user
// traffic is sampled. Closing the manager cancels all work through c.ctx.
func (c *Controller) monitorOutbounds(ctx context.Context, interval time.Duration) {
	next := map[string]time.Time{}
	activeID, activeIdentity := "", ""
	defer func() {
		if activeID != "" {
			_ = c.cancelOperation(activeID)
		}
	}()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.healthWake:
		case <-timer.C:
		}
		timer.Stop()
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		doc := cloneDocument(c.doc)
		broken := c.configError != ""
		identities := map[string]kone.OutboundConfig{}
		for _, outbound := range doc.Config.Outbounds {
			if outbound.IsEnabled() && (outbound.CheckEnabled == nil || *outbound.CheckEnabled) {
				identities[outboundIdentity(doc.Config, outbound)] = outbound
			}
		}
		if op := c.operations[activeID]; op != nil && op.Status == "running" {
			if _, valid := identities[activeIdentity]; !valid || broken {
				op.cancel()
			}
			c.mu.Unlock()
			timer.Reset(100 * time.Millisecond)
			continue
		}
		activeID, activeIdentity = "", ""
		for identity := range next {
			if _, exists := identities[identity]; !exists {
				delete(next, identity)
			}
		}
		wait := interval
		var selected *kone.OutboundConfig
		var selectedDue time.Time
		identity := ""
		now := c.now()
		// Oldest due first: a slow or large list must not starve its tail when
		// early entries become due again before a full pass has completed.
		if !broken {
			for _, outbound := range doc.Config.Outbounds {
				key := outboundIdentity(doc.Config, outbound)
				if _, enabled := identities[key]; !enabled {
					continue
				}
				due := next[key]
				if c.health != nil {
					if entry := c.health.entries[key]; entry != nil {
						if entry.status.Status == "testing" {
							if wait > time.Second {
								wait = time.Second
							}
							continue
						}
						if checked := entry.status.CheckedAt; checked != nil && checked.Add(interval).After(due) {
							due = checked.Add(interval)
						}
					}
				}
				if !due.After(now) {
					if selected == nil || due.Before(selectedDue) {
						selected, identity, selectedDue = &outbound, key, due
					}
					continue
				}
				if delay := due.Sub(now); delay < wait {
					wait = delay
				}
			}
		}
		c.mu.Unlock()
		if selected != nil {
			target := selected.CheckTarget
			if target == "" {
				target = "example.com:443"
			}
			withTLS := selected.CheckTLS == nil || *selected.CheckTLS
			next[identity] = now.Add(interval)
			operation, err := c.testOutbound(OutboundTestRequest{BaseVersion: doc.Version, OutboundID: selected.ID, Target: &target, TLS: &withTLS}, "", true)
			if err == nil {
				activeID, activeIdentity = operation.ID, identity
			}
			wait = 100 * time.Millisecond
		}
		if wait <= 0 {
			wait = time.Millisecond
		}
		timer.Reset(wait)
	}
}

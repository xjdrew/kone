package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLiveCIDRRoutesApplyRollbackAndRelease(t *testing.T) {
	n := newMemoryNetwork()
	sockets := &loopSockets{}
	one := lifecycleEngine(t, n, sockets)
	cancel, done := runReady(t, one)
	defer func() { cancel(); require.NoError(t, waitRun(t, done)); assertReleased(t, n, sockets) }()
	old := one.Snapshot()
	_, release := one.flowSnapshot(netip.MustParseAddr("198.51.100.1"))
	cfg := one.Snapshot().Config
	cfg.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "192.0.2.0/24", Outbound: BuiltinReject}}
	require.NoError(t, one.ReloadVersion(cfg, 42))
	require.Equal(t, uint64(42), one.policy.Load().configurationVersion())
	n.mu.Lock()
	require.True(t, n.routes["192.0.2.0/24"])
	require.True(t, n.routes["198.51.100.0/24"], "established connection keeps its route")
	require.False(t, n.routes["203.0.113.0/24"])
	n.mu.Unlock()
	release()
	n.mu.Lock()
	require.False(t, n.routes["198.51.100.0/24"])
	n.failRoute = true
	n.mu.Unlock()
	require.Error(t, one.Reload(old.Config))
	require.Equal(t, uint64(42), one.policy.Load().configurationVersion())
	n.mu.Lock()
	require.Equal(t, map[string]bool{"192.0.2.0/24": true}, n.routes, "failed addition rolls back every new route")
	n.mu.Unlock()
}

func TestCaptureRoutePlanDeduplicatesDefaultAndIPv6(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Core.IPv6Network = "fd7a:203::1/120"
	cfg.Core.AutoRoute = true
	cfg.Core.AutoRoute6 = true
	cfg.Rule = []RuleConfig{
		{Schema: "IP-CIDR", Pattern: "0.0.0.0/0", Outbound: BuiltinReject},
		{Schema: "IP-CIDR6", Pattern: "::/0", Outbound: BuiltinReject},
		{Schema: "IP-CIDR6", Pattern: "2001:db8::/32", Outbound: BuiltinDirect},
	}
	rule := NewRuleWithGeoIP(cfg.Rule, cfg.Outbounds, nil)
	require.ElementsMatch(t, []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}, captureRoutes(cfg.Core, rule))
}

type routeFailureNetwork struct {
	*memoryNetwork
	removeFailure  string
	restoreFailure string
}

func (n *routeFailureNetwork) AddRoute(ctx context.Context, device Device, subnet *net.IPNet) (Cleanup, error) {
	key := subnet.String()
	if key == n.restoreFailure {
		return nil, errors.New("injected restore failure")
	}
	undo, err := n.memoryNetwork.AddRoute(ctx, device, subnet)
	return func(ctx context.Context) error {
		if n.removeFailure == key {
			n.removeFailure = ""
			return errors.New("injected removal failure")
		}
		return undo(ctx)
	}, err
}

func TestLiveRouteRemovalRollbackAndIPv6(t *testing.T) {
	for _, failRestore := range []bool{false, true} {
		t.Run(fmt.Sprint(failRestore), func(t *testing.T) {
			n := &routeFailureNetwork{memoryNetwork: newMemoryNetwork()}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			one := &One{network: n, routeDevice: n.device, captureRoutes: map[string]Cleanup{}, shutdownTimeout: time.Second, cancel: cancel}
			previous := []string{"192.0.2.0/24", "2001:db8::/32"}
			require.NoError(t, one.updateCaptureRoutes(ctx, previous))
			n.removeFailure = "2001:db8::/32"
			if failRestore {
				n.restoreFailure = "192.0.2.0/24"
			}
			err := one.updateCaptureRoutes(ctx, []string{"203.0.113.0/24"})
			require.Error(t, err)
			if failRestore {
				require.ErrorIs(t, ctx.Err(), context.Canceled)
				require.ErrorContains(t, err, "rollback failed")
			} else {
				require.NoError(t, ctx.Err())
				require.Equal(t, map[string]bool{"192.0.2.0/24": true, "2001:db8::/32": true}, n.routes)
			}
			require.NoError(t, one.restoreCaptureRoutes(t.Context()))
			require.Empty(t, n.routes)
		})
	}
}

func TestFlowRouteAdmissionWaitsForStartupOrCancellation(t *testing.T) {
	for _, cancelStartup := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelStartup), func(t *testing.T) {
			one := testEngine(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			one.started, one.runContext = true, ctx
			release := make(chan func(), 1)
			go func() { _, done := one.flowSnapshot(netip.MustParseAddr("192.0.2.1")); release <- done }()
			select {
			case <-release:
				t.Fatal("admitted a connection before route ownership was ready")
			case <-time.After(20 * time.Millisecond):
			}
			if cancelStartup {
				cancel()
			} else {
				one.reloadMu.Lock()
				one.captureRoutes = map[string]Cleanup{"192.0.2.0/24": nil}
				close(one.ready)
				one.reloadMu.Unlock()
			}
			select {
			case done := <-release:
				one.mu.Lock()
				one.closed = true // shutdown owns cleanup from here
				one.mu.Unlock()
				done()
			case <-time.After(time.Second):
				t.Fatal("flow admission did not leave startup")
			}
			if !cancelStartup {
				require.Equal(t, 1, one.routeReferences["192.0.2.0/24"])
			}
		})
	}
}

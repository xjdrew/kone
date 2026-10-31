package kone

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type lifecycleDNSLease struct {
	*memoryNetwork
	sockets       *loopSockets
	failures      chan error
	configureErr  error
	restoreErr    error
	legacyCalled  atomic.Bool
	restored      atomic.Bool
	listenersLive atomic.Bool
}

func (n *lifecycleDNSLease) ConfigureSystemDNS(context.Context, Device, CoreConfig, DNSConfig) (Cleanup, error) {
	n.legacyCalled.Store(true)
	return nil, errors.New("legacy DNS setup must not replace a monitored lease")
}

func (n *lifecycleDNSLease) ConfigureSystemDNSLease(context.Context, Device, CoreConfig, DNSConfig) (Cleanup, <-chan error, error) {
	return func(ctx context.Context) error {
		n.sockets.mu.Lock()
		address := n.sockets.tcp[0].Addr().String()
		n.sockets.mu.Unlock()
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
		if err == nil {
			n.listenersLive.Store(true)
			connection.Close()
		}
		n.mu.Lock()
		n.events = append(n.events, "restore DNS")
		n.mu.Unlock()
		n.restored.Store(true)
		return n.restoreErr
	}, n.failures, n.configureErr
}

func lifecycleLeaseEngine(t *testing.T, n *lifecycleDNSLease) *One {
	t.Helper()
	one := lifecycleEngine(t, n.memoryNetwork, n.sockets)
	one.network = n
	// The fixture tests lifecycle ownership on every OS without requesting a
	// platform DNS implementation or modifying any real resolver settings.
	snapshot := *one.policy.Load()
	snapshot.cfg = cloneConfig(snapshot.cfg)
	snapshot.cfg.DNS.System = true
	one.policy.Store(&snapshot)
	t.Cleanup(func() { _ = one.Close() })
	return one
}

func assertLeaseRestored(t *testing.T, n *lifecycleDNSLease) {
	t.Helper()
	require.True(t, n.restored.Load())
	require.True(t, n.listenersLive.Load(), "restore DNS guidance before closing its service")
	require.False(t, n.legacyCalled.Load())
	n.mu.Lock()
	defer n.mu.Unlock()
	require.False(t, n.configured)
	require.Empty(t, n.routes)
	dnsIndex, interfaceIndex := -1, -1
	for index, event := range n.events {
		switch event {
		case "restore DNS":
			dnsIndex = index
		case "restore":
			interfaceIndex = index
		}
	}
	require.Greater(t, interfaceIndex, dnsIndex)
	require.EqualValues(t, 1, n.device.closes.Load())
}

func TestSystemDNSLeaseLossStopsAndRestoresEngine(t *testing.T) {
	for _, fault := range []string{"failure", "closed", "nil-error"} {
		t.Run(fault, func(t *testing.T) {
			n := &lifecycleDNSLease{memoryNetwork: newMemoryNetwork(), sockets: new(loopSockets), failures: make(chan error, 1)}
			one := lifecycleLeaseEngine(t, n)
			done := make(chan error, 1)
			go func() { done <- one.Run(t.Context()) }()
			select {
			case <-one.Ready():
			case err := <-done:
				t.Fatalf("lease startup failed: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("lease startup stalled")
			}
			switch fault {
			case "failure":
				n.failures <- errors.New("temporary resolver owner disconnected")
			case "closed":
				close(n.failures)
			case "nil-error":
				n.failures <- nil
			}
			select {
			case err := <-done:
				require.ErrorContains(t, err, "system DNS lease")
			case <-time.After(3 * time.Second):
				t.Fatal("lost system DNS lease left capture running")
			}
			require.NoError(t, one.Close())
			assertLeaseRestored(t, n)
		})
	}
}

func TestSystemDNSLeaseCancellationAndRestoreFailure(t *testing.T) {
	for _, restoreFailed := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "restore-failure"}[restoreFailed], func(t *testing.T) {
			n := &lifecycleDNSLease{memoryNetwork: newMemoryNetwork(), sockets: new(loopSockets), failures: make(chan error)}
			if restoreFailed {
				n.restoreErr = errors.New("temporary resolver removal unconfirmed")
			}
			one := lifecycleLeaseEngine(t, n)
			done := make(chan error, 1)
			go func() { done <- one.Run(t.Context()) }()
			select {
			case <-one.Ready():
			case err := <-done:
				t.Fatalf("lease startup failed: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("lease startup stalled")
			}
			closeErr := one.Close()
			runErr := <-done
			if restoreFailed {
				require.ErrorIs(t, closeErr, n.restoreErr)
				require.ErrorIs(t, runErr, n.restoreErr)
			} else {
				require.NoError(t, closeErr)
				require.NoError(t, runErr)
			}
			assertLeaseRestored(t, n)
		})
	}
}

func TestSystemDNSIncompleteLeaseRollsBackBeforeReady(t *testing.T) {
	for _, fault := range []string{"partial-setup", "missing-monitor"} {
		t.Run(fault, func(t *testing.T) {
			n := &lifecycleDNSLease{memoryNetwork: newMemoryNetwork(), sockets: new(loopSockets)}
			if fault == "partial-setup" {
				n.failures = make(chan error)
				n.configureErr = errors.New("temporary resolver setup interrupted")
			}
			one := lifecycleLeaseEngine(t, n)
			require.ErrorContains(t, one.Run(t.Context()), "configure system DNS")
			select {
			case <-one.Ready():
				t.Fatal("incomplete DNS setup reported ready")
			default:
			}
			assertLeaseRestored(t, n)
		})
	}
}

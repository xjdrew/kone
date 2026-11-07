package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestOutboundMonitorRepeatsWithoutPageAndStopsOnDisable(t *testing.T) {
	var calls atomic.Int32
	c := testController(t, Options{Probe: func(ctx context.Context, cfg *kone.KoneConfig, name, target string, tls bool) ProbeResult {
		require.Equal(t, "office", name)
		require.Equal(t, "example.com:443", target)
		require.True(t, tls)
		calls.Add(1)
		latency := int64(4)
		return ProbeResult{Status: "reachable", Stage: "target_tls", ConnectLatencyMS: &latency}
	}})
	savedHealthOutbound(t, c, "socks5://127.0.0.1:1080")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); c.monitorOutbounds(ctx, 120*time.Millisecond) }()
	require.Eventually(t, func() bool { return calls.Load() >= 2 }, 2*time.Second, 10*time.Millisecond)
	status := healthStatuses(t, c)[0]
	require.True(t, status.Automatic)
	require.Equal(t, "example.com:443", status.Target)
	require.Equal(t, "paused", c.State().DataState)
	r := currentRequest(c)
	outbounds := r.Config["outbounds"].([]any)
	outbounds[0].(map[string]any)["check-enabled"] = false
	_, err := c.Save(r)
	require.NoError(t, err)
	before := calls.Load()
	require.Never(t, func() bool { return calls.Load() > before }, 200*time.Millisecond, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop")
	}
}

func TestOutboundMonitorCancelsChangedConfigurationAndUsesCustomTarget(t *testing.T) {
	started, canceled := make(chan string, 2), make(chan struct{}, 1)
	c := testController(t, Options{Probe: func(ctx context.Context, cfg *kone.KoneConfig, name, target string, tls bool) ProbeResult {
		started <- target
		if target == "example.com:443" {
			<-ctx.Done()
			canceled <- struct{}{}
			return ProbeResult{Status: "canceled"}
		}
		require.False(t, tls)
		return ProbeResult{Status: "reachable", Stage: "connect"}
	}})
	savedHealthOutbound(t, c, "http://127.0.0.1:7078")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go c.monitorOutbounds(ctx, time.Minute)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe not started")
	}
	r := currentRequest(c)
	outbound := r.Config["outbounds"].([]any)[0].(map[string]any)
	outbound["check-target"], outbound["check-tls"] = "149.154.167.50:443", false
	_, err := c.Save(r)
	require.NoError(t, err)
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("old probe not canceled")
	}
	select {
	case target := <-started:
		require.Equal(t, "149.154.167.50:443", target)
	case <-time.After(time.Second):
		t.Fatal("new target not tested")
	}
}

func TestOutboundMonitorChecksEveryOutboundBeforeRepeatingOverdueEntries(t *testing.T) {
	checked := make(chan string, 8)
	c := testController(t, Options{Probe: func(_ context.Context, _ *kone.KoneConfig, name, _ string, _ bool) ProbeResult {
		checked <- name
		return ProbeResult{Status: "reachable", Stage: "connect"}
	}})
	savedHealthOutbound(t, c, "http://127.0.0.1:8080")
	r := currentRequest(c)
	r.Config["outbounds"] = []any{
		map[string]any{"id": "office", "name": "office", "url": "http://127.0.0.1:8080"},
		map[string]any{"id": "second", "name": "second", "url": "http://127.0.0.1:8081"},
		map[string]any{"id": "third", "name": "third", "url": "http://127.0.0.1:8082"},
	}
	_, err := c.Save(r)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go c.monitorOutbounds(ctx, 120*time.Millisecond)
	// Completing a pass takes longer than the interval. Earlier entries are
	// already due again while later entries have not yet been checked.
	for _, expected := range []string{"office", "second", "third"} {
		select {
		case actual := <-checked:
			require.Equal(t, expected, actual)
		case <-time.After(2 * time.Second):
			t.Fatal("an outbound was starved by earlier overdue checks")
		}
	}
}

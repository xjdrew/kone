package desktop

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

type udpDiagnosticNetworkEngine struct {
	*fakeNetworkEngine
	probeMu  sync.Mutex
	udpProbe func(context.Context, string, string, kone.DiagnosticOptions, uint64) (kone.DiagnosticResult, error)
}

func (e *udpDiagnosticNetworkEngine) ProbeDiagnosticRequestVersion(ctx context.Context, outbound, target string, o kone.DiagnosticOptions, v uint64) (kone.DiagnosticResult, error) {
	e.probeMu.Lock()
	probe := e.udpProbe
	e.probeMu.Unlock()
	return probe(ctx, outbound, target, o, v)
}

func TestUDPDiagnosticOptionsAndCancellationCrossHelperIPCWithoutStoppingCapture(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:5353"}
	engine := &udpDiagnosticNetworkEngine{fakeNetworkEngine: newFakeNetworkEngine(t, cfg), udpProbe: func(_ context.Context, outbound, target string, o kone.DiagnosticOptions, v uint64) (kone.DiagnosticResult, error) {
		require.Equal(t, "direct", outbound)
		require.Equal(t, "[::1]:53", target)
		require.Equal(t, "AAAA", o.DNSType)
		require.Equal(t, "ipv6", o.AddressFamily)
		require.Equal(t, uint64(7), v)
		return kone.DiagnosticResult{Protocol: "udp", Stage: "udp_response", Status: "reachable", DNSRCode: "NXDOMAIN", ConfigVersion: v}, nil
	}}
	commandsParent, commandsHelper := net.Pipe()
	eventsParent, eventsHelper := net.Pipe()
	helperDone := make(chan error, 1)
	go func() {
		helperDone <- ServeHelper(t.Context(), commandsHelper, eventsHelper, func(*kone.KoneConfig) (NetworkEngine, error) { return engine, nil })
	}()
	remote, err := NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return commandsParent, eventsParent, nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { remote.Close(); commandsParent.Close(); eventsParent.Close() })
	run := startRemote(t, remote)
	options := kone.DiagnosticOptions{Protocol: "udp", DNSType: "AAAA", AddressFamily: "ipv6"}
	result, err := remote.ProbeDiagnosticRequestVersion(t.Context(), "direct", "[::1]:53", options, 7)
	require.NoError(t, err)
	require.Equal(t, "reachable", result.Status)
	require.Equal(t, "NXDOMAIN", result.DNSRCode)
	entered, canceled := make(chan struct{}), make(chan struct{})
	engine.probeMu.Lock()
	engine.udpProbe = func(ctx context.Context, _ string, _ string, _ kone.DiagnosticOptions, _ uint64) (kone.DiagnosticResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return kone.DiagnosticResult{Protocol: "udp", Status: "canceled"}, nil
	}
	engine.probeMu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	probeDone := make(chan error, 1)
	go func() {
		_, err := remote.ProbeDiagnosticRequestVersion(ctx, "direct", "[::1]:53", options, 7)
		probeDone <- err
	}()
	<-entered
	cancel()
	require.ErrorIs(t, <-probeDone, context.Canceled)
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("helper UDP probe ignored cancellation")
	}
	traffic, _, err := remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{})
	require.NoError(t, err)
	require.Equal(t, uint64(1), traffic.Totals.Active)
	require.NoError(t, remote.Close())
	require.NoError(t, <-run)
	require.NoError(t, <-helperDone)
}

package control

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestUDPDiagnosticAPIProtocolValidationAndCancellation(t *testing.T) {
	var calls atomic.Int32
	c := testController(t, Options{ProbeUDP: func(ctx context.Context, _ *kone.KoneConfig, outbound, target string, o kone.DiagnosticOptions) ProbeResult {
		calls.Add(1)
		require.Equal(t, "dns", o.UDPMode)
		if target == "cancel.invalid:53" {
			<-ctx.Done()
		}
		return ProbeResult{Target: target, Outbound: outbound, Protocol: "udp", Status: "reachable", Stage: "udp_response", DNSRCode: "NXDOMAIN"}
	}})
	owner := owner(t, c)
	for _, body := range []map[string]any{{"target": "127.0.0.1:53", "protocol": "udp", "tls": true}, {"target": "127.0.0.1:53", "protocol": "udp", "udp_mode": "echo"}, {"target": "127.0.0.1:53", "protocol": "icmp"}, {"target": "127.0.0.1:53", "protocol": "udp", "dns_type": "ANY"}} {
		require.Equal(t, 400, request(t, c, owner, "POST", "/api/v1/diagnostics", body).Code)
	}
	w := request(t, c, owner, "POST", "/api/v1/diagnostics", map[string]any{"target": "127.0.0.1:53", "protocol": "udp", "dns_type": "AAAA"})
	require.Equal(t, 202, w.Code, w.Body.String())
	op, err := c.DiagnoseProtocol("127.0.0.1:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, "udp")
	require.NoError(t, err)
	result := waitOperation(t, c, op.ID)
	require.Equal(t, "succeeded", result.Status)
	body := result.Result.(map[string]any)
	require.Equal(t, "udp", body["protocol"])
	require.False(t, body["automatic_rule"].(bool))
	require.False(t, body["suggest_proxy"].(bool))
	require.Equal(t, c.doc.Version, body["results"].([]ProbeResult)[0].ConfigVersion)
	op, err = c.DiagnoseProtocol("cancel.invalid:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, "cancel")
	require.NoError(t, err)
	require.NoError(t, c.cancelOperation(op.ID))
	require.Equal(t, "canceled", waitOperation(t, c, op.ID).Status)
	_, err = c.DiagnoseProtocol("x:53", []string{"missing"}, kone.DiagnosticOptions{Protocol: "udp"}, "")
	require.Error(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	require.Equal(t, "canceled", probeUDPTarget(ctx, cfg, "direct", "127.0.0.1:53", kone.DiagnosticOptions{Protocol: "udp"}).Status)
	cfg.Core.Network = "bad"
	require.Equal(t, "configuration_or_dns", probeUDPTarget(t.Context(), cfg, "direct", "127.0.0.1:53", kone.DiagnosticOptions{Protocol: "udp"}).Stage)
}

func TestDiagnosticRateCountsProbesAndDeduplicatesConcurrentRetries(t *testing.T) {
	var minute atomic.Int64
	start := time.Now()
	var calls atomic.Int32
	c := testController(t, Options{Now: func() time.Time { return start.Add(time.Duration(minute.Load()) * time.Minute) }, ProbeUDP: func(context.Context, *kone.KoneConfig, string, string, kone.DiagnosticOptions) ProbeResult {
		calls.Add(1)
		return ProbeResult{Status: "reachable", Protocol: "udp"}
	}})
	var workers sync.WaitGroup
	ids := make(chan string, 16)
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			op, err := c.DiagnoseProtocol("127.0.0.1:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, "one-request")
			require.NoError(t, err)
			ids <- op.ID
		}()
	}
	workers.Wait()
	close(ids)
	id := ""
	for current := range ids {
		if id == "" {
			id = current
		}
		require.Equal(t, id, current)
	}
	waitOperation(t, c, id)
	for i := 1; i < 32; i++ {
		op, err := c.DiagnoseProtocol("127.0.0.1:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, fmt.Sprint(i))
		require.NoError(t, err)
		waitOperation(t, c, op.ID)
	}
	_, err := c.DiagnoseProtocol("127.0.0.1:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, "limited")
	require.ErrorIs(t, err, ErrDiagnosticRateLimit)
	require.Equal(t, int32(32), calls.Load())
	token := owner(t, c)
	require.Equal(t, 429, request(t, c, token, "POST", "/api/v1/diagnostics", map[string]any{"target": "127.0.0.1:53", "protocol": "udp"}).Code)
	op, err := c.DiagnoseProtocol("127.0.0.1:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, "one-request")
	require.NoError(t, err)
	require.Equal(t, id, op.ID)
	minute.Add(1)
	op, err = c.DiagnoseProtocol("127.0.0.1:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, "next-minute")
	require.NoError(t, err)
	waitOperation(t, c, op.ID)
}

type udpProbeMemoryEngine struct {
	*memoryEngine
	probe func(context.Context, string, string, kone.DiagnosticOptions, uint64) (kone.DiagnosticResult, error)
}

func (e *udpProbeMemoryEngine) ProbeDiagnosticRequestVersion(ctx context.Context, outbound, target string, o kone.DiagnosticOptions, v uint64) (kone.DiagnosticResult, error) {
	return e.probe(ctx, outbound, target, o, v)
}

func TestUDPDiagnosticUsesRunningOwnerAndNeverRebuildsASecondResolver(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(fmt.Sprint(supported), func(t *testing.T) {
			engine := &udpProbeMemoryEngine{memoryEngine: newMemoryEngine(), probe: func(_ context.Context, outbound, target string, o kone.DiagnosticOptions, v uint64) (kone.DiagnosticResult, error) {
				require.Equal(t, "udp", o.Protocol)
				return ProbeResult{Status: "reachable", Protocol: "udp", ConfigVersion: v}, nil
			}}
			c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) {
				if supported {
					return engine, nil
				}
				return engine.memoryEngine, nil
			}, ProbeUDP: func(context.Context, *kone.KoneConfig, string, string, kone.DiagnosticOptions) ProbeResult {
				t.Fatal("active capture must never create a second resolver")
				return ProbeResult{}
			}})
			enable(t, c)
			require.NoError(t, c.Start(t.Context()))
			op, err := c.DiagnoseProtocol("127.0.0.1:53", nil, kone.DiagnosticOptions{Protocol: "udp"}, "")
			require.NoError(t, err)
			result := waitOperation(t, c, op.ID).Result.(map[string]any)["results"].([]ProbeResult)[0]
			if supported {
				require.Equal(t, "reachable", result.Status)
			} else {
				require.Equal(t, "unsupported", result.Status)
			}
			require.Equal(t, c.doc.Version, result.ConfigVersion)
		})
	}
}

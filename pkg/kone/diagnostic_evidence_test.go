package kone

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRejectedDiagnosticNeverClaimsMeasuredConnectivity(t *testing.T) {
	cleanProxyEnv(t)
	for _, scenario := range []struct {
		name, outbound, target, stage, status string
	}{
		{"invalid-target", BuiltinDirect, "missing-port", "configuration", "failed"},
		{"rejected-policy", BuiltinReject, "192.0.2.1:443", "policy", "failed"},
		{"missing-outbound", "missing", "192.0.2.1:443", "configuration", "failed"},
		{"virtual-destination", BuiltinDirect, "10.192.0.8:443", "virtual_destination", "unsupported"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DNS.Servers = []string{"127.0.0.1:53"}
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("rejected diagnostic must not connect")
				return nil, nil
			}
			var final DiagnosticResult
			ctx := WithDiagnosticProgress(t.Context(), func(result DiagnosticResult) { final = result })
			result, err := one.ProbeDiagnostic(ctx, scenario.outbound, scenario.target, true)
			require.NoError(t, err)
			require.Equal(t, scenario.stage, result.Stage)
			require.Equal(t, scenario.status, result.Status)
			require.Equal(t, "unknown", result.Host.Status)
			require.Nil(t, result.ConnectLatencyMS)
			require.Equal(t, "unknown", result.Protocols.TCP.Status)
			require.False(t, result.Protocols.TCP.Tested)
			require.False(t, result.Protocols.TLS.Tested)
			require.False(t, result.Protocols.UDP.Tested)
			require.Equal(t, "complete", final.Progress.Stage)
			require.Equal(t, result.Status, final.Status)
		})
	}
}

func TestCanceledEndpointProbeHasNoFailureOrLatencyEvidence(t *testing.T) {
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	one.policy.Load().outbounds.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := one.ProbeDiagnostic(ctx, BuiltinDirect, "192.0.2.1:443", false)
	require.NoError(t, err)
	require.Equal(t, "canceled", result.Status)
	require.Equal(t, "unknown", result.Host.Status)
	require.Nil(t, result.ConnectLatencyMS)
	require.Equal(t, "unknown", result.Protocols.TCP.Status)
	require.False(t, result.Protocols.TCP.Tested)
	require.Equal(t, "complete", result.Progress.Stage)
}

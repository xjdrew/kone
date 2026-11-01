package kone

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShadowsocksProgressDoesNotInventTargetOrUDPConfirmation(t *testing.T) {
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:5353"}
	cfg.Outbounds = []OutboundConfig{{Name: "encrypted", URL: "ss://aes-128-gcm:private@127.0.0.1:8388"}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) { return diagnosticTransport{}, nil }
	var snapshots []DiagnosticResult
	ctx := WithDiagnosticProgress(t.Context(), func(result DiagnosticResult) { snapshots = append(snapshots, result) })
	result, err := one.ProbeDiagnostic(ctx, "encrypted", "unreachable.invalid:443", false)
	require.NoError(t, err)
	require.Equal(t, "unknown", result.Status)
	require.Equal(t, "healthy", result.Host.Status)
	require.NotNil(t, result.ConnectLatencyMS)
	require.Equal(t, "unknown", result.Protocols.TCP.Status)
	require.Equal(t, "unknown", result.Protocols.UDP.Status)
	require.False(t, result.Protocols.UDP.Tested)
	require.Equal(t, "connect", snapshots[0].Progress.Stage)
	require.Equal(t, "testing", snapshots[0].Host.Status)
	require.Equal(t, "proxy_handshake", snapshots[1].Progress.Stage)
	require.Equal(t, "complete", snapshots[len(snapshots)-1].Progress.Stage)
	require.Equal(t, "testing", snapshots[0].Host.Status, "a later result cannot mutate the earlier progress snapshot")
}

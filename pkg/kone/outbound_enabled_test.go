package kone

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisabledOutboundNeverDialsFallsBackOrBypassesRules(t *testing.T) {
	cleanProxyEnv(t)
	disabled := false
	for _, url := range []string{"http://127.0.0.1:8080", "socks5://127.0.0.1:1080", "ss://aes-128-gcm:secret@127.0.0.1:8388"} {
		config := []OutboundConfig{{ID: "stable-office", Name: "office", URL: url, Enabled: &disabled, UDPFallback: BuiltinDirect}}
		outbounds, err := NewOutbounds(config)
		require.NoError(t, err)
		outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("disabled proxy must not connect to its old URL or to a direct fallback")
			return nil, errors.New("unexpected dial")
		}
		_, err = outbounds.DialContext(context.Background(), "office", "example.com:443")
		require.ErrorIs(t, err, ErrOutboundDisabled)
		require.ErrorIs(t, err, ErrRejected)
		_, err = outbounds.UDPOutbound("office")
		require.ErrorIs(t, err, ErrOutboundDisabled)
		_, err = outbounds.DialUDPContext(context.Background(), "office", "example.com:443")
		require.ErrorIs(t, err, ErrOutboundDisabled)
		require.False(t, outbounds.SupportsUDP("office"))
		rule := NewRule([]RuleConfig{{Schema: "FINAL", Outbound: "office"}}, config)
		outbounds.bypassEndpoints(rule)
		require.False(t, rule.Decide("127.0.0.1", "tcp", 443).Protected, "a disabled proxy endpoint is not permission to bypass a reject policy")
		cfg := DefaultConfig()
		cfg.DNS.Servers = []string{"127.0.0.1:53"}
		cfg.Outbounds = config
		cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "office"}}
		require.NoError(t, cfg.Validate(), "rules may keep referencing disabled outbounds")
		decision, err := ExplainRouting(cfg, "example.com", "tcp", 443)
		require.ErrorIs(t, err, ErrOutboundDisabled)
		require.Equal(t, "office", decision.Outbound)
		require.Empty(t, decision.EffectiveOutbound)
		one, err := FromConfig(cfg)
		require.NoError(t, err)
		one.policy.Load().outbounds.dial = outbounds.dial
		result, err := one.ProbeDiagnostic(context.Background(), "office", "example.com:443", false)
		require.NoError(t, err)
		require.Equal(t, "failed", result.Status)
		require.Equal(t, "policy", result.Stage)
		require.Equal(t, "not_attempted", result.DNSPath)
		require.NoError(t, one.Close())
	}
	_, err := NewOutbounds([]OutboundConfig{{Name: "bad", URL: "invalid", Enabled: &disabled}})
	require.Error(t, err, "disabled entries still require a valid proxy URL")
}

func TestOutboundEnableSnapshotCopiesPointersAndKeepsExistingPolicy(t *testing.T) {
	cleanProxyEnv(t)
	enabled := true
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	cfg.Outbounds = []OutboundConfig{{ID: "stable-office", Name: "office", URL: "http://127.0.0.1:8080", Enabled: &enabled}}
	cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "office"}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	enabled = false
	require.True(t, one.Snapshot().Config.Outbounds[0].IsEnabled(), "configuration input must not mutate a published snapshot")
	old := one.policy.Load()
	probeError := errors.New("old policy dialed")
	old.outbounds.dial = func(context.Context, string, string) (net.Conn, error) { return nil, probeError }
	next := one.Snapshot().Config
	value := false
	next.Outbounds[0].Enabled = &value
	require.NoError(t, one.Reload(next))
	_, err = one.policy.Load().outbounds.DialContext(context.Background(), "office", "example.com:443")
	require.ErrorIs(t, err, ErrOutboundDisabled)
	_, err = old.outbounds.DialContext(context.Background(), "office", "example.com:443")
	require.ErrorIs(t, err, probeError, "existing sessions keep their old enabled policy")
	snapshot := one.Snapshot().Config
	*snapshot.Outbounds[0].Enabled = true
	require.False(t, one.Snapshot().Config.Outbounds[0].IsEnabled(), "returned snapshots must not mutate enable state")
	require.True(t, (OutboundConfig{}).IsEnabled(), "omitted enabled remains compatible")
}

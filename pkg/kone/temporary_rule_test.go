package kone

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTemporaryRulesExpireOnlyForNewDecisions(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	expires := now.Add(time.Minute)
	rule := NewRule([]RuleConfig{{ID: "temporary", Schema: "DOMAIN", Pattern: "example.com", Outbound: "reject", ExpiresAt: expires.Format(time.RFC3339)}, {ID: "fallback", Schema: "FINAL", Outbound: "direct"}}, nil)
	rule.now = func() time.Time { return now }
	old := rule.Decide("example.com", "tcp", 443)
	require.Equal(t, "reject", old.Outbound)
	require.NotEmpty(t, old.ExpiresAt)
	now = expires
	require.Equal(t, "direct", rule.Decide("example.com", "tcp", 443).Outbound)
	require.Equal(t, "direct", rule.ProxyDNS("example.com", nil))
	require.Equal(t, "reject", old.Outbound, "existing flow keeps its already selected decision")
	other := NewRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "example.com", Outbound: "reject"}}, nil)
	other.now = rule.now
	require.Equal(t, "reject", other.Decide("example.com", "udp", 53).Outbound)
	zero := NewRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "example.com", Outbound: "reject", ExpiresAt: "0001-01-01T00:00:00Z"}}, nil)
	require.Equal(t, "direct", zero.Decide("example.com", "tcp", 443).Outbound, "an explicit zero-time deadline is expired, not permanent")
	before := expires.Add(-time.Second)
	transition := NewRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "example.com", Outbound: "direct", ExpiresAt: expires.Format(time.RFC3339)}, {Schema: "DOMAIN", Pattern: "example.com", Outbound: "reject"}}, nil)
	transition.now = func() time.Time { return before }
	require.Equal(t, CaptureOutbound, transition.ProxyDNS("example.com", nil), "temporary direct must not cache a real address that bypasses its post-expiry policy")
	require.Equal(t, "direct", transition.Decide("example.com", "tcp", 443).Outbound)
	before = expires
	require.Equal(t, "reject", transition.ProxyDNS("example.com", nil))
	require.Equal(t, "reject", transition.Decide("example.com", "tcp", 443).Outbound)
}

func TestTemporaryConfigurationRejectsAmbiguousCaptureLifetimes(t *testing.T) {
	cfg := DefaultConfig()
	for _, entry := range []RuleConfig{
		{Schema: "DOMAIN", Pattern: "example.com", Outbound: "direct", ExpiresAt: "tomorrow"},
		{Schema: "IP-CIDR", Pattern: "192.0.2.0/24", Outbound: "direct", ExpiresAt: "2026-11-01T00:00:00Z"},
		{Schema: "FINAL", Outbound: "direct", ExpiresAt: "2026-11-01T00:00:00Z"},
	} {
		cfg.Rule = []RuleConfig{entry}
		require.Error(t, cfg.Validate())
	}
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN-SUFFIX", Pattern: "example.com", Outbound: "direct", ExpiresAt: "2020-01-01T00:00:00Z"}}
	require.NoError(t, cfg.Validate(), "past deadlines remain readable and inactive")
}

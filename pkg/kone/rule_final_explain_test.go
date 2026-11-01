package kone

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoutingSimulationIdentifiesOrdinaryFinalAndProtectedRules(t *testing.T) {
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://endpoint.example:8080"}}
	cfg.Rule = []RuleConfig{
		{ID: "domain-rule", Schema: "DOMAIN", Pattern: "matched.example", Outbound: "office"},
		{ID: "fallback-rule", Schema: "FINAL", Outbound: BuiltinReject},
	}
	for _, scenario := range []struct {
		target, id, kind, name, outbound string
		order                            int
	}{
		{"matched.example", "domain-rule", "DOMAIN", "DOMAIN matched.example", "office", 1},
		{"unmatched.example", "fallback-rule", "FINAL", "FINAL", BuiltinReject, 2},
		{"192.0.2.1", "fallback-rule", "FINAL", "FINAL", BuiltinReject, 2},
		{"endpoint.example", "protected:endpoint", "PROTECTED", "Proxy endpoint bypass", BuiltinDirect, 0},
	} {
		for _, port := range []uint16{80, 443} {
			for _, protocol := range []string{"tcp", "udp"} {
				decision, err := ExplainRouting(cfg, scenario.target, protocol, port)
				if scenario.outbound == "office" && protocol == "udp" {
					require.ErrorIs(t, err, ErrUDPUnsupported)
				} else if scenario.outbound == BuiltinReject && protocol == "udp" {
					require.ErrorIs(t, err, ErrRejected)
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, scenario.id, decision.RuleID)
				require.Equal(t, scenario.kind, decision.RuleType)
				require.Equal(t, scenario.name, decision.RuleName)
				require.Equal(t, scenario.order, decision.RuleOrder)
				require.Equal(t, scenario.outbound, decision.Outbound)
			}
		}
	}
	cfg.Rule = cfg.Rule[:1]
	decision, err := ExplainRouting(cfg, "unmatched.example", "tcp", 443)
	require.NoError(t, err)
	require.Equal(t, "FINAL", decision.RuleType)
	require.Equal(t, "builtin:default", decision.RuleID)
	require.Equal(t, "Default direct", decision.RuleName)
	require.Equal(t, "builtin", decision.RuleSource)
	require.Equal(t, "no rule matched", decision.Reason)
	require.Zero(t, decision.RuleOrder)
}

func TestConditionalFinalRemainsCompatibleAndIdentifiable(t *testing.T) {
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.Rule = []RuleConfig{{ID: "legacy-final", Schema: "FINAL", Protocol: "udp", Ports: []uint16{53}, Outbound: BuiltinReject}}
	require.NoError(t, cfg.Validate(), "existing conditional FINAL configurations retain their scope")
	matched, err := ExplainRouting(cfg, "example.com", "udp", 53)
	require.ErrorIs(t, err, ErrRejected)
	require.Equal(t, "legacy-final", matched.RuleID)
	require.Equal(t, "FINAL", matched.RuleType)
	require.Equal(t, BuiltinReject, matched.Outbound)
	unmatched, err := ExplainRouting(cfg, "example.com", "tcp", 443)
	require.NoError(t, err)
	require.Equal(t, "builtin:default", unmatched.RuleID)
	require.Equal(t, "FINAL", unmatched.RuleType)
	require.Equal(t, BuiltinDirect, unmatched.Outbound)
}

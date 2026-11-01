package kone

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestProtocolAndPortRulesShareFlowAndDNSEnvelope(t *testing.T) {
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, `[[outbounds]]
name='office'
url='http://127.0.0.1:8080'
[[rules]]
id='secure-site'
source='user'
type='DOMAIN'
pattern='example.com'
protocol='tcp'
ports=[443]
outbound='office'
[[rules]]
id='blocked-port'
type='DOMAIN'
pattern='blocked.example'
protocol='tcp'
ports=[25]
outbound='reject'
[[rules]]
id='default'
type='FINAL'
outbound='direct'`)
	rule := NewRule(cfg.Rule, cfg.Outbounds)
	decision := rule.Decide("example.com", "tcp", 443)
	require.Equal(t, "office", decision.Outbound)
	require.Equal(t, "secure-site", decision.RuleID)
	require.Equal(t, "user", decision.RuleSource)
	require.Equal(t, BuiltinDirect, rule.Decide("example.com", "udp", 443).Outbound)
	require.Equal(t, BuiltinDirect, rule.Decide("example.com", "tcp", 80).Outbound)
	require.Equal(t, CaptureOutbound, rule.Proxy("example.com"))
	require.Equal(t, OutboundProxy, rule.OutboundType(CaptureOutbound))
	require.Equal(t, CaptureOutbound, rule.Proxy("blocked.example"), "TCP-only reject must not refuse DNS for other protocols")
	require.Equal(t, BuiltinReject, rule.Decide("blocked.example", "tcp", 25).Outbound)
	require.Equal(t, BuiltinDirect, rule.Decide("blocked.example", "udp", 25).Outbound)
	cfg.Rule[0].Ports[0] = 80
	require.Equal(t, "office", rule.Decide("example.com", "tcp", 443).Outbound, "selector slices must be immutable")
	answer := &dns.Msg{Answer: []dns.RR{&dns.CNAME{Target: "example.com."}}}
	require.Equal(t, "office", rule.DecideDNS("alias.example", answer, "tcp", 443).Outbound)
	require.Equal(t, BuiltinDirect, rule.DecideDNS("alias.example", answer, "udp", 443).Outbound)
}

func TestRuleIDsStableAndRoutingSimulationHasNoNetworkSideEffects(t *testing.T) {
	cleanProxyEnv(t)
	rules := []RuleConfig{{Schema: "DOMAIN", Pattern: "first.example", Outbound: BuiltinReject}, {Schema: "DOMAIN", Pattern: "second.example", Outbound: BuiltinDirect}}
	first := NewRule(rules, nil)
	second := NewRule([]RuleConfig{rules[1], rules[0]}, nil)
	require.Equal(t, first.Decide("first.example", "tcp", 80).RuleID, second.Decide("first.example", "tcp", 80).RuleID)
	require.NotEqual(t, first.Decide("first.example", "tcp", 80).RuleOrder, second.Decide("first.example", "tcp", 80).RuleOrder)
	one := testEngine(t)
	decision, err := one.ExplainDecision("example.com:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, "A", decision.Outbound)
	require.Equal(t, uint64(1), decision.ConfigVersion)
	decision, err = one.ExplainDecision("127.0.0.1", "tcp", 80)
	require.NoError(t, err)
	require.True(t, decision.Protected)
	require.Equal(t, BuiltinDirect, decision.Outbound)
	decision, err = one.ExplainDecision("example.com", "udp", 443)
	require.ErrorIs(t, err, ErrUDPUnsupported)
	require.Equal(t, "A", decision.Outbound)
	require.Empty(t, decision.EffectiveOutbound)
	cfg := one.Snapshot().Config
	cfg.Outbounds[0].UDPFallback = BuiltinDirect
	decision, err = ExplainRouting(cfg, "example.com", "udp", 443)
	require.NoError(t, err)
	require.True(t, decision.Fallback)
	require.Equal(t, BuiltinDirect, decision.EffectiveOutbound)
	for _, input := range []struct {
		target, protocol string
		port             uint16
	}{{"example.com", "sctp", 80}, {"example.com", "tcp", 0}, {"[2001:db8::1]:443", "tcp", 0}, {"https://example.com", "tcp", 443}, {"example.com:80", "tcp", 443}} {
		_, err = one.ExplainDecision(input.target, input.protocol, input.port)
		require.Error(t, err)
	}
	_, err = ExplainRouting(nil, "example.com", "tcp", 443)
	require.Error(t, err)
	first.DirectDomain("192.0.2.1")
	require.True(t, first.Decide(netip.MustParseAddr("192.0.2.1"), "udp", 80).Protected)
}

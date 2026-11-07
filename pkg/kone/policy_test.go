package kone

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestBasePolicyValidationAndLegacyRecognition(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Outbounds = []OutboundConfig{{Name: "proxy", URL: "http://127.0.0.1:7078", UDPFallback: "direct"}}
	cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "proxy"}}
	mode, _ := PolicyMode(cfg)
	require.Equal(t, "custom", mode, "legacy selective capture must not be labeled global")
	cfg.Policy.Mode = "proxy-first"
	cfg.Policy.IPv4Only = true
	require.ErrorContains(t, cfg.ValidatePolicy(), "IPv4 capture")
	cfg.Core.AutoRoute, cfg.Core.OutboundInterface = true, "test-uplink"
	require.ErrorContains(t, cfg.ValidatePolicy(), "UDP direct")
	cfg.Policy.UDPException = true
	require.NoError(t, cfg.ValidatePolicy())
	cfg.Core.IPv6Network = "fd00:192::1/64"
	cfg.Policy.IPv4Only = false
	require.ErrorContains(t, cfg.ValidatePolicy(), "IPv6")
	cfg.Policy.IPv4Only = true
	require.NoError(t, cfg.ValidatePolicy())
	cfg.Rule[0].Protocol = "tcp"
	require.ErrorContains(t, cfg.ValidatePolicy(), "unconditional final")
	cfg.Policy.Mode = ""
	require.NoError(t, cfg.ValidatePolicy(), "legacy configurations retain existing behavior")
}

func TestPolicyProtectsHostsButAllowsExplicitPrivateProxyRules(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Mode = "proxy-first"
	outbounds := []OutboundConfig{{Name: "proxy", URL: "http://127.0.0.1:7078"}}
	cfg.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "192.168.0.0/16", Outbound: "proxy"}}
	cfg.Rule = append(cfg.Rule, DefaultLANRules(cfg.Core)...)
	cfg.Rule = append(cfg.Rule, RuleConfig{Schema: "FINAL", Outbound: "proxy"})
	rule := NewRule(cfg.Rule, outbounds)
	rule.protectPolicy(cfg)
	for _, address := range []string{"127.0.0.1", "::1"} {
		decision := rule.Decide(net.ParseIP(address), "tcp", 443)
		require.True(t, decision.Protected)
		require.Equal(t, BuiltinDirect, decision.Outbound)
	}
	for _, address := range []string{"192.168.2.9", "149.154.167.50"} {
		decision := rule.Decide(net.ParseIP(address), "tcp", 443)
		require.False(t, decision.Protected)
		require.Equal(t, "proxy", decision.Outbound)
	}
	for _, address := range []string{"172.20.0.8", "169.254.1.1", "fd00::5", "fe80::1"} {
		decision := rule.Decide(net.ParseIP(address), "tcp", 443)
		require.False(t, decision.Protected)
		require.Equal(t, BuiltinDirect, decision.Outbound)
		require.Equal(t, "policy-lan", decision.RuleSource)
	}
	message := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "printer.local.", Rrtype: dns.TypeA}, A: net.ParseIP("192.168.2.9")}}}
	require.Equal(t, "proxy", rule.DecideDNS("printer.local", message, "tcp", 443).Outbound)
	rule = NewRule([]RuleConfig{{Schema: "FINAL", Outbound: "proxy"}}, outbounds)
	rule.protectPolicy(cfg)
	for _, address := range []string{"192.168.2.9", "172.20.0.8", "fd00::5", "10.192.0.5"} {
		require.Equal(t, "proxy", rule.Decide(net.ParseIP(address), "tcp", 443).Outbound, "deleting a direct rule must take effect")
	}
}

func TestLANRuleTemplateDeduplicatesOverlappingNetworks(t *testing.T) {
	rules := lanRules([]string{"192.168.1.2/24", "192.168.0.0/16", "192.168.1.0/24", "fd00::/64", "fc00::/7"})
	require.Len(t, rules, 2)
	require.Equal(t, "192.168.0.0/16", rules[0].Pattern)
	require.Equal(t, "fc00::/7", rules[1].Pattern)
	require.Equal(t, "IP-CIDR6", rules[1].Schema)
}

func TestExplicitPolicyRejectsBrokenDefaultsAndRetainsLegacyIntent(t *testing.T) {
	var absent *KoneConfig
	require.NoError(t, absent.ValidatePolicy())
	mode, _ := PolicyMode(absent)
	require.Equal(t, "custom", mode)
	cfg := DefaultConfig()
	cfg.Rule = nil
	mode, _ = PolicyMode(cfg)
	require.Equal(t, "direct-first", mode)
	cfg.Policy.Mode = "unknown"
	require.ErrorContains(t, cfg.ValidatePolicy(), "policy.mode")
	cfg.Policy = PolicyConfig{Mode: "proxy-first", IPv4Only: true}
	cfg.Core.AutoRoute, cfg.Core.OutboundInterface = true, "uplink"
	cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "missing"}}
	require.ErrorContains(t, cfg.ValidatePolicy(), "does not exist")
	disabled := false
	cfg.Outbounds = []OutboundConfig{{Name: "missing", URL: "socks5://127.0.0.1:1080", Enabled: &disabled}}
	require.ErrorContains(t, cfg.ValidatePolicy(), "disabled")
	cfg.Rule[0].Outbound = BuiltinReject
	mode, outbound := PolicyMode(cfg)
	require.Equal(t, "custom", mode)
	require.Equal(t, BuiltinReject, outbound)
	cfg.Policy.Mode = "custom"
	require.NoError(t, cfg.ValidatePolicy(), "reject defaults remain explicit custom policy")
}

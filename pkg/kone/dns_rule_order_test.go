package kone

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSDecisionsHonorGlobalExplicitRuleOrder(t *testing.T) {
	message := &dns.Msg{Answer: []dns.RR{&dns.CNAME{Target: "cdn.example."}, &dns.A{A: net.ParseIP("203.0.113.9")}, &dns.AAAA{AAAA: net.ParseIP("2001:db8::9")}}}
	proxy := []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
	cases := []struct {
		name     string
		rules    []RuleConfig
		outbound string
		order    int
	}{
		{"domain direct precedes proxy final", []RuleConfig{{Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}, BuiltinDirect, 1},
		{"earlier IP wins over domain direct", []RuleConfig{{Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: "office"}, {Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: BuiltinReject}}, "office", 1},
		{"earlier CNAME wins over domain direct", []RuleConfig{{Schema: "DOMAIN", Pattern: "cdn.example", Outbound: "office"}, {Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect}}, "office", 1},
		{"later IP cannot replace domain direct", []RuleConfig{{Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect}, {Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: "office"}, {Schema: "FINAL", Outbound: BuiltinReject}}, BuiltinDirect, 1},
		{"earlier IPv6 direct wins over proxy final", []RuleConfig{{Schema: "IP-CIDR6", Pattern: "2001:db8::/64", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}, BuiltinDirect, 1},
		{"earlier domain proxy wins over CNAME direct", []RuleConfig{{Schema: "DOMAIN", Pattern: "origin.example", Outbound: "office"}, {Schema: "DOMAIN", Pattern: "cdn.example", Outbound: BuiltinDirect}}, "office", 1},
		{"explicit answer rule beats implicit default", []RuleConfig{{Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: BuiltinReject}}, BuiltinReject, 1},
		{"implicit default stays when no explicit target matches", []RuleConfig{{Schema: "DOMAIN", Pattern: "unrelated.example", Outbound: "office"}}, BuiltinDirect, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := NewRule(tc.rules, proxy)
			for _, response := range []*dns.Msg{message, {Answer: []dns.RR{message.Answer[2], message.Answer[1], message.Answer[0]}}} {
				decision := rule.DecideDNS("origin.example", response, "tcp", 443)
				require.Equal(t, tc.outbound, decision.Outbound)
				require.Equal(t, tc.order, decision.RuleOrder)
			}
			require.Equal(t, rule.Decide("origin.example", "tcp", 443), rule.DecideDNS("origin.example", nil, "tcp", 443), "missing DNS evidence does not cause speculative lookups")
		})
	}
}

func TestDNSRuleOrderKeepsProtectedEndpointsCaptureAndExpiry(t *testing.T) {
	message := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.ParseIP("203.0.113.9")}}}
	rule := NewRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinReject}, {Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: "office"}}, []OutboundConfig{{Name: "office"}})
	rule.DirectDomain("origin.example")
	require.True(t, rule.DecideDNS("origin.example", message, "tcp", 443).Protected)
	rule = NewRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinReject}}, nil)
	rule.DirectDomain("203.0.113.9")
	decision := rule.DecideDNS("origin.example", message, "tcp", 443)
	require.True(t, decision.Protected)
	require.Equal(t, BuiltinDirect, decision.Outbound)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, config := range []RuleConfig{
		{Schema: "DOMAIN", Pattern: "origin.example", Outbound: "office", Protocol: "udp", Ports: []uint16{443}},
		{Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)},
	} {
		rule := NewRule([]RuleConfig{config, {Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: BuiltinReject}, {Schema: "FINAL", Outbound: BuiltinDirect}}, []OutboundConfig{{Name: "office"}})
		rule.now = func() time.Time { return now }
		decision := rule.DecideDNS("origin.example", message, "", 0)
		require.Equal(t, CaptureOutbound, decision.Outbound)
		require.True(t, decision.CaptureOnly)
		require.Equal(t, 1, decision.RuleOrder)
		if config.ExpiresAt != "" {
			rule.now = func() time.Time { return now.Add(2 * time.Minute) }
			decision = rule.DecideDNS("origin.example", message, "", 0)
			require.Equal(t, BuiltinReject, decision.Outbound)
			require.Equal(t, 2, decision.RuleOrder)
		}
	}
}

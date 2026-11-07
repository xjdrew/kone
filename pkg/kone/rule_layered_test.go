package kone

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func layeredAnswer(name string, addresses ...string) *dns.Msg {
	message := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA)
	for _, address := range addresses {
		message.Answer = append(message.Answer, &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(address)})
	}
	return message
}
func layeredRule(rules []RuleConfig) *Rule {
	cfg := DefaultConfig()
	cfg.Policy.RuleVersion = 2
	cfg.Rule = rules
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
	rule := NewRule(cfg.Rule, cfg.Outbounds)
	rule.protectPolicy(cfg)
	return rule
}
func TestLayeredEvidenceOrderAndCandidateBinding(t *testing.T) {
	response := layeredAnswer("origin.example", "203.0.113.9", "198.51.100.9")
	rules := []RuleConfig{{Schema: "IP-CIDR", Pattern: "198.51.100.0/24", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}
	rule := layeredRule(rules)
	require.Equal(t, "dns_required", rule.DecideDNS("origin.example", nil, "tcp", 443).Evidence)
	for _, addresses := range [][]string{{"203.0.113.9", "198.51.100.9"}, {"198.51.100.9", "203.0.113.9"}} {
		result := rule.DecideDNS("origin.example", layeredAnswer("origin.example", addresses...), "tcp", 443)
		require.Equal(t, BuiltinDirect, result.Outbound)
		require.Equal(t, "ip", result.Pool)
		require.Equal(t, []string{"198.51.100.9"}, result.Candidates)
	}
	rules = append(rules, RuleConfig{Schema: "DOMAIN", Pattern: "origin.example", Outbound: "office"})
	rule = layeredRule(rules)
	result := rule.DecideDNS("origin.example", response, "tcp", 443)
	require.Equal(t, "domain", result.Pool)
	require.Equal(t, "office", result.Outbound)
	// Same-pool order is unchanged; original query wins before CNAME aliases.
	response.Answer = append(response.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: "origin.example."}, Target: "alias.example."}, &dns.A{Hdr: dns.RR_Header{Name: "unrelated.example."}, A: net.ParseIP("127.0.0.1")})
	rule = layeredRule(append([]RuleConfig{{Schema: "DOMAIN", Pattern: "alias.example", Outbound: BuiltinReject}}, rules...))
	require.Equal(t, "office", rule.DecideDNS("origin.example", response, "tcp", 443).Outbound)
	rule = layeredRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "alias.example", Outbound: BuiltinReject}})
	require.Equal(t, BuiltinReject, rule.DecideDNS("origin.example", response, "tcp", 443).Outbound)
	response.Answer = append(response.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example."}, Target: "origin.example."})
	require.Equal(t, "dns_failed", rule.DecideDNS("origin.example", response, "tcp", 443).Evidence)
	rule = layeredRule(rules)
	result = rule.DecideDNS("origin.example", layeredAnswer("origin.example", "127.0.0.1", "203.0.113.9"), "tcp", 443)
	require.True(t, result.Protected)
	require.Equal(t, []string{"127.0.0.1"}, result.Candidates)
	response = layeredAnswer("origin.example")
	response.Rcode = dns.RcodeNameError
	require.Equal(t, "dns_failed", rule.DecideDNS("origin.example", response, "tcp", 443).Evidence)
}
func TestLayeredUnknownFlowConditionsAndScopedFinalRemainExplicit(t *testing.T) {
	for _, action := range []string{BuiltinDirect, BuiltinReject, "office"} {
		rule := layeredRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "service.example", Outbound: action, Protocol: "tcp", Ports: []uint16{443}}, {Schema: "FINAL", Outbound: "office", Protocol: "udp"}})
		require.Equal(t, "flow_required", rule.DecideDNS("service.example", nil, "", 0).Evidence)
		response := layeredAnswer("service.example", "203.0.113.9")
		require.Equal(t, action, rule.DecideDNS("service.example", response, "tcp", 443).Outbound)
		require.Equal(t, BuiltinDirect, rule.DecideDNS("service.example", response, "tcp", 80).Outbound)
		require.Equal(t, "office", rule.DecideDNS("service.example", response, "udp", 80).Outbound)
	}
	rule := layeredRule([]RuleConfig{{Schema: "DOMAIN", Pattern: "service.example", Outbound: BuiltinReject, ExpiresAt: time.Now().Add(-time.Second).Format(time.RFC3339)}})
	require.Equal(t, BuiltinDirect, rule.DecideDNS("service.example", layeredAnswer("service.example", "203.0.113.9"), "tcp", 443).Outbound)
	cfg := DefaultConfig()
	cfg.Policy.RuleVersion = 2
	decision, err := ExplainRouting(cfg, "cold.example", "tcp", 443)
	require.NoError(t, err)
	require.Equal(t, "dns_required", decision.Evidence)
	require.Empty(t, decision.EffectiveOutbound)
	cfg.Policy.RuleVersion = 3
	require.Error(t, cfg.Validate())
}
func TestLayeredColdDNSAndFlowUseSameAllowedAddress(t *testing.T) {
	for _, action := range []string{BuiltinDirect, "office"} {
		t.Run(action, func(t *testing.T) {
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				reply := layeredAnswer(r.Question[0].Name, "203.0.113.9", "198.51.100.9")
				reply.SetReply(r)
				_ = w.WriteMsg(reply)
			})
			upstream := startDNSListeners(t, handler, handler)
			cfg := DefaultConfig()
			cfg.Policy.RuleVersion = 2
			cfg.DNS.Servers = []string{upstream}
			cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
			cfg.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "198.51.100.0/24", Outbound: action}, {Schema: "FINAL", Outbound: "office"}}
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			reply, err := one.dns.HandleQuery(t.Context(), new(dns.Msg).SetQuestion("cold.example.", dns.TypeA), "udp", "client")
			require.NoError(t, err)
			fake := net.ParseIP(dnsAddresses(reply)[0])
			require.True(t, one.dnsTable.Contains(fake))
			destination := M.SocksaddrFromNet(&net.TCPAddr{IP: fake, Port: 443})
			target, err := one.flows.resolveDestination(t.Context(), one.policy.Load(), destination, false, nil)
			require.NoError(t, err)
			defer target.release()
			require.Equal(t, action, target.outbound)
			require.Equal(t, "198.51.100.9:443", target.address)
			// Re-evaluation after TTL expiry preserves the candidate restriction.
			expireRealResolution(t, one, one.dnsTable, "cold.example")
			target, err = one.flows.resolveDestination(t.Context(), one.policy.Load(), destination, false, nil)
			require.NoError(t, err)
			defer target.release()
			require.Equal(t, "198.51.100.9:443", target.address)
			cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "cold.example", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}
			require.NoError(t, one.Reload(cfg))
			reply, err = one.dns.HandleQuery(t.Context(), new(dns.Msg).SetQuestion("cold.example.", dns.TypeA), "udp", "client")
			require.NoError(t, err)
			require.Equal(t, fake.String(), dnsAddresses(reply)[0], "direct domain exceptions retain their identity")
		})
	}
}

func TestLayeredDirectAfterReloadReturnsCurrentDNSRequestIdentity(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := layeredAnswer(r.Question[0].Name, "8.8.8.8")
		reply.SetReply(r)
		_ = w.WriteMsg(reply)
	})
	upstream := startDNSListeners(t, handler, handler)
	cfg := DefaultConfig()
	cfg.Policy.RuleVersion = 2
	cfg.DNS.Servers = []string{upstream}
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "cached.example", Outbound: "office"}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	first := new(dns.Msg).SetQuestion("cached.example.", dns.TypeA)
	first.Id = 1
	reply, err := one.dns.HandleQuery(t.Context(), first, "udp", "client")
	require.NoError(t, err)
	require.True(t, one.dnsTable.IsLocalIP(reply.Answer[0].(*dns.A).A))
	cfg.Rule = nil
	require.NoError(t, one.Reload(cfg))
	next := new(dns.Msg).SetQuestion("Cached.Example.", dns.TypeA)
	next.Id = 99
	reply, err = one.dns.HandleQuery(t.Context(), next, "tcp", "client")
	require.NoError(t, err)
	require.Equal(t, next.Id, reply.Id)
	require.Equal(t, next.Question, reply.Question)
	require.Equal(t, "8.8.8.8", reply.Answer[0].(*dns.A).A.String())
}

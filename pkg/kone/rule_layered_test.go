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

func TestLayeredDNSFiltersProtectedCandidatesAndPreservesFailureSemantics(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg).SetReply(r)
		switch normalizeDomain(r.Question[0].Name) {
		case "missing.example":
			reply.Rcode = dns.RcodeNameError
		case "empty.example":
		case "unrelated.example":
			reply.Answer = layeredAnswer("other.example", "8.8.8.8").Answer
		case "mixed.example":
			reply.Answer = append(reply.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "alias.example."})
			if r.Question[0].Qtype == dns.TypeAAAA {
				for _, ip := range []string{"::1", "2001:4860:4860::8888"} {
					reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP(ip)})
				}
			} else {
				reply.Answer = append(reply.Answer, layeredAnswer("alias.example", "127.0.0.1", "8.8.8.8").Answer...)
			}
		default:
			reply.Answer = layeredAnswer(r.Question[0].Name, "8.8.8.8").Answer
		}
		_ = w.WriteMsg(reply)
	})
	upstream := startDNSListeners(t, handler, handler)
	cfg := DefaultConfig()
	cfg.Policy.RuleVersion = 2
	cfg.DNS.Servers = []string{upstream}
	cfg.Core.IPv6Network = "fd7a:204:9::1/112"
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "blocked.example", Outbound: BuiltinReject}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	for _, family := range []uint16{dns.TypeA, dns.TypeAAAA} {
		reply, err := one.dns.HandleQuery(t.Context(), new(dns.Msg).SetQuestion("mixed.example.", family), "udp", "client")
		require.NoError(t, err)
		require.Len(t, reply.Answer, 2)
		expected := "127.0.0.1"
		if family == dns.TypeAAAA {
			expected = "::1"
		}
		require.Equal(t, []string{expected}, dnsAddresses(reply))
	}
	for _, name := range []string{"missing.example", "empty.example", "blocked.example"} {
		reply, err := one.dns.HandleQuery(t.Context(), new(dns.Msg).SetQuestion(name+".", dns.TypeA), "udp", "client")
		require.NoError(t, err)
		require.Empty(t, reply.Answer)
		expected := dns.RcodeSuccess
		if name == "missing.example" {
			expected = dns.RcodeNameError
		}
		if name == "blocked.example" {
			expected = dns.RcodeRefused
		}
		require.Equal(t, expected, reply.Rcode)
	}
	_, err = one.dns.queryLayered(t.Context(), one.policy.Load(), new(dns.Msg).SetQuestion("unrelated.example.", dns.TypeA))
	require.ErrorContains(t, err, "evidence")
	cfg.Core.IPv6Network = ""
	cfg.Core.Network = "10.203.0.1/29"
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN-SUFFIX", Pattern: "example", Protocol: "tcp", Ports: []uint16{443}, Outbound: BuiltinDirect}}
	small, err := FromConfig(cfg)
	require.NoError(t, err)
	defer small.Close()
	reply, err := small.dns.queryLayered(t.Context(), small.policy.Load(), new(dns.Msg).SetQuestion("first.example.", dns.TypeAAAA))
	require.NoError(t, err)
	require.Empty(t, reply.Answer)
	_, err = small.dns.queryLayered(t.Context(), small.policy.Load(), new(dns.Msg).SetQuestion("first.example.", dns.TypeA))
	require.NoError(t, err)
	for _, name := range []string{"third.example.", "fourth.example.", "fifth.example."} {
		_, err = small.dns.queryLayered(t.Context(), small.policy.Load(), new(dns.Msg).SetQuestion(name, dns.TypeA))
		require.NoError(t, err)
	}
	_, err = small.dns.queryLayered(t.Context(), small.policy.Load(), new(dns.Msg).SetQuestion("second.example.", dns.TypeA))
	require.ErrorContains(t, err, "allocated")
}

func TestLayeredFlowsRetainFailureEvidenceAndExplicitUDPPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.RuleVersion = 2
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "blocked.example", Outbound: BuiltinReject}, {Schema: "IP-CIDR", Pattern: "8.8.8.8/32", Outbound: "office"}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	observer := NewTrafficObserver(ObservationOptions{})
	resolve := func(address string, udp bool) (flowTarget, error) {
		observation := observer.Begin(FlowRecord{Protocol: "tcp", Target: address})
		target, err := one.flows.resolveDestination(t.Context(), one.policy.Load(), M.ParseSocksaddr(address), udp, observation)
		if target.release != nil {
			target.release()
		}
		observation.Finish(err, false)
		return target, err
	}
	_, err = resolve("[2001:4860:4860::8888]:443", false)
	require.ErrorContains(t, err, "IPv6")
	_, err = resolve("10.192.0.100:443", false)
	require.ErrorContains(t, err, "unknown virtual")
	blocked := one.dnsTable.Set("blocked.example", BuiltinReject)
	target, err := resolve(net.JoinHostPort(blocked.IP.String(), "443"), false)
	require.ErrorIs(t, err, ErrRejected)
	require.Equal(t, "domain", target.decision.Pool)
	_, err = resolve("8.8.8.8:443", true)
	require.ErrorContains(t, err, "UDP")
	cfg.Outbounds[0].UDPFallback = BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	target, err = resolve("8.8.8.8:443", true)
	require.NoError(t, err)
	require.Equal(t, BuiltinDirect, target.outbound)
	require.Equal(t, "8.8.8.8:443", target.realDestination)
	records := observer.Snapshot(TrafficQuery{}).Records
	require.Contains(t, records[0].AuthorizedCandidates, "8.8.8.8")
	require.Equal(t, "ip", records[0].DecisionPool)
}

package kone

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestDomainDNSPolicyDoesNotLeakAAAAWithoutIPv6Capture(t *testing.T) {
	cleanProxyEnv(t)
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4-only", true: "dual-stack"}[ipv6], func(t *testing.T) {
			var queries atomic.Int32
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				queries.Add(1)
				reply := new(dns.Msg)
				reply.SetReply(request)
				reply.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")}}
				w.WriteMsg(reply)
			})
			upstream := startDNSListeners(t, handler, handler)
			cfg := DefaultConfig()
			cfg.DNS.Servers = []string{upstream}
			cfg.Outbounds = []OutboundConfig{{Name: "broken", URL: "http://proxy-endpoint.example:8080"}}
			cfg.Rule = []RuleConfig{
				{Schema: "DOMAIN", Pattern: "proxy.example", Outbound: "broken"},
				{Schema: "DOMAIN", Pattern: "conditional.example", Protocol: "tcp", Ports: []uint16{443}, Outbound: "broken"},
				{Schema: "DOMAIN", Pattern: "blocked.example", Outbound: BuiltinReject},
				{Schema: "DOMAIN", Pattern: "conditional-reject.example", Protocol: "udp", Ports: []uint16{53}, Outbound: BuiltinReject},
				{Schema: "DOMAIN", Pattern: "proxy-endpoint.example", Outbound: BuiltinReject},
				{Schema: "FINAL", Outbound: BuiltinDirect},
			}
			if ipv6 {
				cfg.Core.IPv6Network = "fd7a:203::1/120"
			}
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			for _, name := range []string{"proxy.example", "conditional.example", "conditional-reject.example"} {
				request := new(dns.Msg)
				request.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
				reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
				require.NoError(t, err)
				require.Equal(t, dns.RcodeSuccess, reply.Rcode)
				if ipv6 {
					require.Len(t, reply.Answer, 1)
					require.True(t, one.dnsTable6.IsLocalIP(reply.Answer[0].(*dns.AAAA).AAAA))
				} else {
					require.Empty(t, reply.Answer, "NODATA lets the client use its A/Fake-IP path")
					require.Empty(t, reply.Ns)
					require.Empty(t, reply.Extra, "no real address may escape through additional records")
					require.Equal(t, "ipv6-policy", one.DNSQueries()[0].Cache)
				}
				request.Question[0].Qtype = dns.TypeA
				reply, err = one.dns.HandleQuery(t.Context(), request, "tcp", "client")
				require.NoError(t, err)
				require.Len(t, reply.Answer, 1)
				require.True(t, one.dnsTable.IsLocalIP(reply.Answer[0].(*dns.A).A))
			}
			request := new(dns.Msg)
			request.SetQuestion("blocked.example.", dns.TypeAAAA)
			reply, err := one.dns.HandleQuery(t.Context(), request, "tcp", "client")
			require.NoError(t, err)
			require.Equal(t, dns.RcodeRefused, reply.Rcode)
			require.Zero(t, queries.Load(), "selected proxy/reject policy needs no speculative upstream lookup")
			for _, name := range []string{"direct.example", "proxy-endpoint.example"} {
				request.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
				reply, err = one.dns.HandleQuery(t.Context(), request, "udp", "client")
				require.NoError(t, err)
				require.Equal(t, []string{"2001:db8::9"}, dnsAddresses(reply), "direct names and protected proxy endpoints keep real AAAA answers")
			}
			require.Equal(t, int32(2), queries.Load())
			require.False(t, cfg.Core.AutoRoute6)
			if !ipv6 {
				require.Empty(t, one.Snapshot().Config.Core.IPv6Network, "the DNS guard never enables host IPv6 capture")
			}
		})
	}
}

func TestUncapturedAAAAKeepsCNAMEAndFinalRuleOrder(t *testing.T) {
	cleanProxyEnv(t)
	for _, scenario := range []struct {
		name  string
		rules []RuleConfig
		code  int
		real  bool
	}{
		{"earlier CNAME proxy", []RuleConfig{{Schema: "DOMAIN", Pattern: "cdn.example", Outbound: "broken"}, {Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: BuiltinDirect}}, dns.RcodeSuccess, false},
		{"earlier CNAME reject", []RuleConfig{{Schema: "DOMAIN", Pattern: "cdn.example", Outbound: BuiltinReject}, {Schema: "FINAL", Outbound: BuiltinDirect}}, dns.RcodeRefused, false},
		{"earlier origin direct", []RuleConfig{{Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect}, {Schema: "DOMAIN", Pattern: "cdn.example", Outbound: "broken"}, {Schema: "FINAL", Outbound: BuiltinReject}}, dns.RcodeSuccess, true},
		{"proxy FINAL", []RuleConfig{{Schema: "DOMAIN", Pattern: "elsewhere.example", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "broken"}}, dns.RcodeSuccess, false},
		{"conditional FINAL", []RuleConfig{{Schema: "FINAL", Protocol: "tcp", Ports: []uint16{443}, Outbound: "broken"}}, dns.RcodeSuccess, false},
		{"implicit direct", nil, dns.RcodeSuccess, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				reply := new(dns.Msg)
				reply.SetReply(request)
				reply.Answer = []dns.RR{
					&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "cdn.example."},
					&dns.AAAA{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")},
				}
				w.WriteMsg(reply)
			})
			cfg := DefaultConfig()
			cfg.DNS.Servers = []string{startDNSListeners(t, handler, handler)}
			cfg.Outbounds = []OutboundConfig{{Name: "broken", URL: "http://127.0.0.1:1"}}
			cfg.Rule = scenario.rules
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			request := new(dns.Msg)
			request.SetQuestion("origin.example.", dns.TypeAAAA)
			reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
			require.NoError(t, err)
			require.Equal(t, scenario.code, reply.Rcode)
			if scenario.real {
				require.Equal(t, []string{"2001:db8::9"}, dnsAddresses(reply))
			} else {
				require.Empty(t, reply.Answer)
			}
		})
	}
}

func TestBrokenDomainProxyClosesCapturedTCPWithoutDirectRetry(t *testing.T) {
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Outbounds = []OutboundConfig{{Name: "broken", URL: "http://127.0.0.1:8080"}}
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "example.com", Outbound: "broken"}, {Schema: "FINAL", Outbound: BuiltinDirect}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeAAAA)
	reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	require.Empty(t, reply.Answer)
	request.Question[0].Qtype = dns.TypeA
	reply, err = one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	fake := reply.Answer[0].(*dns.A).A
	var attempts []string
	one.policy.Load().outbounds.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		attempts = append(attempts, address)
		return nil, errors.New("intentional proxy connection failure")
	}
	for _, port := range []uint16{80, 443} {
		client, accepted := net.Pipe()
		client.SetReadDeadline(time.Now().Add(time.Second))
		one.flows.NewConnectionEx(t.Context(), accepted, M.ParseSocksaddr("192.0.2.2:40000"), M.SocksaddrFromNet(&net.TCPAddr{IP: fake, Port: int(port)}), nil)
		_, err := client.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF, "failed outbound closes the already accepted local connection")
		client.Close()
	}
	require.Equal(t, []string{"127.0.0.1:8080", "127.0.0.1:8080"}, attempts, "no direct destination retry follows a proxy failure")
}

func TestAAAAPolicyChangesDoNotReuseAnUncapturedDirectAnswer(t *testing.T) {
	cleanProxyEnv(t)
	var queries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")}}
		w.WriteMsg(reply)
	})
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{startDNSListeners(t, handler, handler)}
	cfg.Outbounds = []OutboundConfig{{Name: "broken", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "changing.example", Outbound: BuiltinDirect}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	request := new(dns.Msg)
	request.SetQuestion("changing.example.", dns.TypeAAAA)
	reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	require.Len(t, reply.Answer, 1)
	cfg.Rule[0].Outbound = "broken"
	require.NoError(t, one.Reload(cfg))
	reply, err = one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	require.Empty(t, reply.Answer)
	require.Equal(t, int32(1), queries.Load(), "a new capture policy must guard even a previously real cached AAAA answer")
	cfg.Rule[0].Outbound = BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	reply, err = one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	require.Equal(t, []string{"2001:db8::9"}, dnsAddresses(reply), "NODATA is not a sticky domain-wide negative cache")
}

func TestCapturedAAAAHonorsAddressRulesBeforeAndAfterDomainRules(t *testing.T) {
	cleanProxyEnv(t)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")}}
		w.WriteMsg(reply)
	})
	upstream := startDNSListeners(t, handler, handler)
	for _, scenario := range []struct {
		name, outbound string
		domainFirst    bool
	}{
		{"earlier address proxy", "broken", false},
		{"earlier address reject", BuiltinReject, false},
		{"earlier domain direct", "broken", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Core.IPv6Network = "fd7a:203::1/120"
			cfg.DNS.Servers = []string{upstream}
			cfg.Outbounds = []OutboundConfig{{Name: "broken", URL: "http://127.0.0.1:1"}}
			address := RuleConfig{Schema: "IP-CIDR6", Pattern: "2001:db8::/64", Outbound: scenario.outbound}
			domain := RuleConfig{Schema: "DOMAIN", Pattern: "origin.example", Outbound: BuiltinDirect}
			cfg.Rule = []RuleConfig{address, domain, {Schema: "FINAL", Outbound: "broken"}}
			if scenario.domainFirst {
				cfg.Rule[0], cfg.Rule[1] = domain, address
			}
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			request := new(dns.Msg)
			request.SetQuestion("origin.example.", dns.TypeAAAA)
			reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
			require.NoError(t, err)
			if scenario.outbound == BuiltinReject {
				require.Equal(t, dns.RcodeRefused, reply.Rcode)
			} else if scenario.domainFirst {
				require.Equal(t, []string{"2001:db8::9"}, dnsAddresses(reply))
			} else {
				require.Len(t, reply.Answer, 1)
				require.True(t, one.dnsTable6.IsLocalIP(reply.Answer[0].(*dns.AAAA).AAAA))
			}
		})
	}
}

package kone

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestServiceBindingPolicyKeepsOwnerBaseCNAMEOrderAndProtection(t *testing.T) {
	cleanProxyEnv(t)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: request.Question[0].Qclass, Ttl: 60}, Target: "cdn.example."},
			&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeHTTPS, Class: request.Question[0].Qclass, Ttl: 60}, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2001:db8::9")}}}}},
		}
		reply.Extra = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeAAAA, Class: request.Question[0].Qclass, Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")}}
		w.WriteMsg(reply)
	})
	upstream := startDNSListeners(t, handler, handler)
	for _, scenario := range []struct {
		name, owner string
		rules       []RuleConfig
		code        int
		passthrough bool
	}{
		{"base proxy", "_8443._https.base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "base.example", Outbound: "mono"}}, dns.RcodeSuccess, false},
		{"earlier owner direct", "_8443._https.base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "_8443._https.base.example", Outbound: BuiltinDirect}, {Schema: "DOMAIN", Pattern: "base.example", Outbound: "mono"}}, dns.RcodeSuccess, true},
		{"earlier base proxy", "_8443._https.base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "base.example", Outbound: "mono"}, {Schema: "DOMAIN", Pattern: "_8443._https.base.example", Outbound: BuiltinDirect}}, dns.RcodeSuccess, false},
		{"earlier CNAME proxy", "base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "cdn.example", Outbound: "mono"}, {Schema: "DOMAIN", Pattern: "base.example", Outbound: BuiltinDirect}}, dns.RcodeSuccess, false},
		{"earlier direct beats CNAME", "base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "base.example", Outbound: BuiltinDirect}, {Schema: "DOMAIN", Pattern: "cdn.example", Outbound: "mono"}}, dns.RcodeSuccess, true},
		{"base reject", "_8443._https.base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "base.example", Outbound: BuiltinReject}}, dns.RcodeRefused, false},
		{"protected base", "_8443._https.endpoint.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "_8443._https.endpoint.example", Outbound: BuiltinReject}, {Schema: "FINAL", Outbound: "mono"}}, dns.RcodeSuccess, true},
		{"invalid port prefix stays an owner", "_invalid._https.base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "base.example", Outbound: "mono"}}, dns.RcodeSuccess, true},
		{"other scheme stays an owner", "_8443._other.base.example", []RuleConfig{{Schema: "DOMAIN", Pattern: "base.example", Outbound: "mono"}}, dns.RcodeSuccess, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DNS.Servers = []string{upstream}
			cfg.Outbounds = []OutboundConfig{{Name: "mono", URL: "http://endpoint.example:8080"}}
			cfg.Rule = scenario.rules
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			request := new(dns.Msg)
			request.SetQuestion(dns.Fqdn(scenario.owner), dns.TypeHTTPS)
			request.SetEdns0(4096, true)
			request.CheckingDisabled = true
			reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
			require.NoError(t, err)
			require.Equal(t, scenario.code, reply.Rcode)
			if scenario.passthrough {
				require.Len(t, reply.Answer, 2)
				require.NotEmpty(t, reply.Extra)
			} else {
				require.Empty(t, reply.Answer)
				require.Empty(t, reply.Extra)
				require.False(t, reply.AuthenticatedData, "policy-generated NODATA never claims DNSSEC validation")
			}
			request.Question[0].Qclass = dns.ClassCHAOS
			reply, err = one.dns.HandleQuery(t.Context(), request, "udp", "client")
			require.NoError(t, err)
			require.Len(t, reply.Answer, 2, "non-IN queries retain their existing DNS semantics")
		})
	}
	for _, scenario := range []struct{ owner, expected string }{
		{"example.com.", "example.com"}, {"_sip._tcp.example.com.", "example.com"}, {"_443._https.example.com.", "example.com"},
		{"_._tcp.example.com.", "_._tcp.example.com"}, {"_sip.example.com.", "_sip.example.com"},
	} {
		require.Equal(t, scenario.expected, serviceBindingBaseName(scenario.owner, dns.TypeSVCB))
	}
}

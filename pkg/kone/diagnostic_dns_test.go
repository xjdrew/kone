package kone

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDiagnosticConnectionDefaultPortAndValidation(t *testing.T) {
	for input, expected := range map[string]string{"example.com": "example.com:80", "192.0.2.1": "192.0.2.1:80", "::1": "[::1]:80", "[::1]": "[::1]:80", "[::1]:443": "[::1]:443", "example.com:8443": "example.com:8443"} {
		actual, err := NormalizeConnectionTarget(input)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
	for _, input := range []string{"", "example.com:0", "example.com:", "example.com:bad", "https://example.com", "a:b:c", "0.0.0.0", "x:65536"} {
		_, err := NormalizeConnectionTarget(input)
		require.Error(t, err, input)
	}
}

func TestDNSComparisonUsesOSLookupAndDoesNotInventWireEvidence(t *testing.T) {
	for _, kind := range []string{"A", "AAAA"} {
		options := DiagnosticOptions{Protocol: "dns", DNSName: "Example.COM.", DNSType: kind}
		result, err := probeSystemDNS(t.Context(), options, func(_ context.Context, network, host string) ([]net.IP, error) {
			require.Equal(t, "example.com", host)
			if kind == "A" {
				require.Equal(t, "ip4", network)
			} else {
				require.Equal(t, "ip6", network)
			}
			return []net.IP{net.ParseIP("2001:db8::1")}, nil
		})
		require.NoError(t, err)
		require.Equal(t, "answered", result.Status)
		require.Equal(t, "system", result.Scope)
		require.Equal(t, []string{"2001:db8::1"}, result.DNSAnswers)
		require.Empty(t, result.DNSRCode)
		require.Nil(t, result.ConnectLatencyMS)
	}
	for _, fault := range []error{&net.DNSError{IsNotFound: true}, context.DeadlineExceeded, nil} {
		result, err := probeSystemDNS(t.Context(), DiagnosticOptions{Protocol: "dns"}, func(context.Context, string, string) ([]net.IP, error) { return nil, fault })
		require.NoError(t, err)
		if errors.Is(fault, context.DeadlineExceeded) {
			require.Equal(t, "failed", result.Status)
		} else {
			require.Equal(t, "no_records", result.Status)
		}
	}
	for _, options := range []DiagnosticOptions{{Protocol: "tcp"}, {Protocol: "dns", DNSName: "127.0.0.1"}, {Protocol: "dns", DNSName: "::1"}, {Protocol: "dns", DNSName: "example.com:53"}, {Protocol: "dns", DNSType: "ANY"}, {Protocol: "dns", TLS: true}, {Protocol: "dns", UDPMode: "dns"}, {Protocol: "dns", AddressFamily: "ipv6"}} {
		_, err := ProbeSystemDNS(t.Context(), options)
		require.Error(t, err)
	}
}

func TestKONEDNSComparisonUsesClientPolicyAndReportsPausedScope(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		switch request.Question[0].Name {
		case "missing.example.":
			reply.Rcode = dns.RcodeNameError
		case "empty.example.":
		case "failed.example.":
			reply.Rcode = dns.RcodeServerFailure
		default:
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")}}
		}
		require.NoError(t, w.WriteMsg(reply))
	})
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{startDNSListeners(t, handler, handler)}
	cfg.Outbounds = []OutboundConfig{{Name: "proxy", URL: "http://127.0.0.1:9"}}
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "proxy.example", Outbound: "proxy"}, {Schema: "FINAL", Outbound: BuiltinDirect}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	for name, status := range map[string]string{"direct.example": "answered", "proxy.example": "answered", "missing.example": "no_records", "empty.example": "no_records", "failed.example": "failed"} {
		result, err := one.ProbeDiagnosticRequestVersion(t.Context(), "kone", name, DiagnosticOptions{Protocol: "dns", DNSName: name}, 0)
		require.NoError(t, err)
		require.Equal(t, status, result.Status)
		require.Equal(t, "saved_configuration", result.Scope)
		if name == "proxy.example" {
			require.NotEmpty(t, result.DNSVirtualAddresses)
			require.NotContains(t, result.DNSAnswers[0], "192.0.2.7")
		}
		if name == "direct.example" {
			require.Contains(t, result.DNSAnswers[0], "192.0.2.7")
			require.Empty(t, result.DNSVirtualAddresses)
		}
	}
	require.Len(t, one.DNSQueries(), 5)
	require.Equal(t, "control", one.DNSQueries()[0].Scope)
	result, err := one.ProbeDiagnosticRequestVersion(t.Context(), "kone", "x.example", DiagnosticOptions{Protocol: "dns", DNSName: "x.example"}, 999)
	require.NoError(t, err)
	require.Equal(t, "not_applied", result.Status)
	_, err = one.ProbeDiagnosticRequestVersion(t.Context(), "arbitrary-outbound", "x.example", DiagnosticOptions{Protocol: "dns", DNSName: "x.example"}, 0)
	require.Error(t, err)
	require.NoError(t, one.Close())
	_, err = one.ProbeDiagnosticRequestVersion(t.Context(), "kone", "x.example", DiagnosticOptions{Protocol: "dns", DNSName: "x.example"}, 0)
	require.ErrorContains(t, err, "stopped")
}

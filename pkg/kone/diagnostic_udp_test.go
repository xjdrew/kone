package kone

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type diagnosticDNSConn struct {
	diagnosticTransport
	query  *dns.Msg
	mode   string
	closed atomic.Bool
}

func (c *diagnosticDNSConn) Close() error { c.closed.Store(true); return nil }
func (c *diagnosticDNSConn) SetDeadline(time.Time) error {
	if c.mode == "deadline_error" {
		return errors.New("deadline failure")
	}
	return nil
}
func (c *diagnosticDNSConn) Write(data []byte) (int, error) {
	c.query = new(dns.Msg)
	if err := c.query.Unpack(data); err != nil {
		return 0, err
	}
	if c.mode == "write_error" {
		return 0, errors.New("write failed")
	}
	if c.mode == "short_write" {
		return len(data) - 1, nil
	}
	return len(data), nil
}
func (c *diagnosticDNSConn) Read(data []byte) (int, error) {
	if c.mode == "timeout" {
		return 0, &net.DNSError{Err: "no response", IsTimeout: true}
	}
	r := new(dns.Msg)
	r.SetReply(c.query)
	switch c.mode {
	case "nxdomain":
		r.Rcode = dns.RcodeNameError
	case "refused":
		r.Rcode = dns.RcodeRefused
	case "truncated":
		r.Truncated = true
	case "wrong_id":
		r.Id++
	case "wrong_question":
		r.Question = []dns.Question{{Name: "another.invalid.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	case "echo":
		r = c.query
	case "malformed":
		return copy(data, []byte{1, 2}), nil
	}
	packet, _ := r.Pack()
	return copy(data, packet), nil
}

func udpDiagnosticEngine(t *testing.T, outbounds ...OutboundConfig) *One {
	t.Helper()
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Outbounds = outbounds
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, one.Close()) })
	return one
}

func TestUDPDiagnosticOptionsRejectAmbiguousProtocolsAndUnboundedNames(t *testing.T) {
	options, err := (DiagnosticOptions{Protocol: "udp"}).Normalize()
	require.NoError(t, err)
	require.Equal(t, "dns", options.UDPMode)
	require.Equal(t, "example.com", options.DNSName)
	require.Equal(t, "A", options.DNSType)
	require.Equal(t, "auto", options.AddressFamily)
	for _, bad := range []DiagnosticOptions{{Protocol: "quic"}, {UDPMode: "dns"}, {Protocol: "udp", TLS: true}, {Protocol: "udp", UDPMode: "echo"}, {Protocol: "udp", DNSName: "http://private"}, {Protocol: "udp", DNSName: "a..invalid"}, {Protocol: "udp", DNSName: strings.Repeat("a", 254)}, {Protocol: "udp", DNSType: "ANY"}, {Protocol: "udp", AddressFamily: "all"}} {
		_, err := bad.Normalize()
		require.Error(t, err, bad)
	}
}

func TestUDPDiagnosticRequiresMatchedDNSResponseAndSeparatesDNSOutcome(t *testing.T) {
	for _, mode := range []string{"success", "nxdomain", "refused", "truncated", "wrong_id", "wrong_question", "echo", "malformed", "timeout", "write_error", "short_write", "deadline_error"} {
		t.Run(mode, func(t *testing.T) {
			one := udpDiagnosticEngine(t)
			conn := &diagnosticDNSConn{mode: mode}
			calls := 0
			one.policy.Load().outbounds.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				calls++
				require.Equal(t, "udp4", network)
				require.Equal(t, "127.0.0.1:53", address)
				return conn, nil
			}
			var progress []DiagnosticResult
			ctx := WithDiagnosticProgress(t.Context(), func(value DiagnosticResult) { progress = append(progress, value) })
			result, err := one.ProbeDiagnosticRequestVersion(ctx, BuiltinDirect, "127.0.0.1:53", DiagnosticOptions{Protocol: "udp"}, 0)
			require.NoError(t, err)
			require.Equal(t, 1, calls)
			require.True(t, conn.closed.Load())
			require.Equal(t, "udp", result.Protocol)
			require.Nil(t, result.ConnectLatencyMS, "opening a UDP socket does not measure TCP connectivity")
			require.Equal(t, "unknown", result.Protocols.TCP.Status)
			require.False(t, result.Protocols.TCP.Tested)
			require.False(t, result.Protocols.TLS.Tested)
			require.Equal(t, "complete", result.Progress.Stage)
			require.Equal(t, "complete", progress[len(progress)-1].Progress.Stage)
			if mode == "success" || mode == "nxdomain" || mode == "refused" || mode == "truncated" {
				require.Equal(t, "reachable", result.Status)
				require.Equal(t, "udp_response", result.Stage)
				require.NotEmpty(t, result.DNSRCode)
				require.Equal(t, mode == "truncated", result.DNSTruncated)
				require.Equal(t, "validated_dns_response", result.PeerKind)
				require.Equal(t, "healthy", result.Protocols.UDP.Status)
				require.True(t, result.Protocols.UDP.Tested)
				require.Equal(t, "validated_dns_response", result.Protocols.UDP.Evidence)
				require.Equal(t, 3, result.Progress.Completed)
			} else {
				require.NotEqual(t, "reachable", result.Status)
				if mode == "timeout" {
					require.Equal(t, "unknown", result.Status)
				}
				require.Empty(t, result.DNSRCode)
				require.False(t, result.Protocols.UDP.Tested, "no matching DNS reply means no confirmed UDP evidence")
			}
			require.Equal(t, "example.com", result.DNSName)
			require.False(t, progress[0].Protocols.UDP.Tested, "final evidence cannot mutate an earlier progress snapshot")
		})
	}
}

func TestUDPDiagnosticRejectsFallbackDisabledVirtualAndUnappliedBeforeNetwork(t *testing.T) {
	disabled := false
	one := udpDiagnosticEngine(t, OutboundConfig{Name: "http", URL: "http://private-user:private-password@127.0.0.1:1", UDPFallback: BuiltinDirect}, OutboundConfig{Name: "disabled", URL: "socks5://127.0.0.1:1", Enabled: &disabled})
	require.NoError(t, one.SetConfigVersion(17))
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("policy/capability/identity failure must not dial")
		return nil, errors.New("unexpected")
	}
	for _, tc := range []struct {
		name, target, stage, status string
		version                     uint64
	}{{"http", "unresolved.invalid:53", "capability", "unsupported", 17}, {"disabled", "unresolved.invalid:53", "policy", "failed", 17}, {BuiltinReject, "127.0.0.1:53", "policy", "failed", 17}, {BuiltinDirect, "10.192.0.8:53", "virtual_destination", "unsupported", 17}, {BuiltinDirect, "127.0.0.1:53", "configuration", "not_applied", 18}, {BuiltinDirect, "bad/url", "configuration", "failed", 17}} {
		r, err := one.ProbeDiagnosticRequestVersion(t.Context(), tc.name, tc.target, DiagnosticOptions{Protocol: "udp"}, tc.version)
		require.NoError(t, err)
		require.Equal(t, tc.stage, r.Stage)
		require.Equal(t, tc.status, r.Status)
		require.NotContains(t, r.Message, "private-password")
		require.Nil(t, r.ConnectLatencyMS)
		require.False(t, r.Protocols.TCP.Tested)
		require.False(t, r.Protocols.UDP.Tested)
	}
	_, err := one.ProbeDiagnosticRequestVersion(t.Context(), BuiltinDirect, "127.0.0.1:53", DiagnosticOptions{Protocol: "udp", TLS: true}, 17)
	require.Error(t, err)
}

func TestUDPDiagnosticUsesPinnedResolverAndExplicitAddressFamily(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.Question[0].Name == "empty.invalid." {
			reply.Rcode = dns.RcodeNameError
		} else if r.Question[0].Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
		} else {
			reply.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("::1")}}
		}
		w.WriteMsg(reply)
	})
	resolver := startDNSListeners(t, handler, handler)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{resolver}
	cfg.Outbounds = []OutboundConfig{{Name: "socks", URL: "socks5://127.0.0.1:1"}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	for _, family := range []string{"auto", "ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			one.policy.Load().outbounds.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				if family == "ipv6" {
					require.Equal(t, "udp6", network)
					require.Equal(t, "[::1]:53", address)
				} else {
					require.Equal(t, "udp4", network)
					require.Equal(t, "127.0.0.1:53", address)
				}
				return &diagnosticDNSConn{}, nil
			}
			r, err := one.ProbeDiagnosticRequestVersion(t.Context(), BuiltinDirect, "resolver.invalid:53", DiagnosticOptions{Protocol: "udp", AddressFamily: family, DNSType: "AAAA"}, 0)
			require.NoError(t, err)
			require.Equal(t, "reachable", r.Status)
			require.Equal(t, "AAAA", r.DNSType)
			require.Equal(t, "engine_dns_snapshot", r.DNSPath)
		})
	}
	for _, tc := range []struct{ name, target, family string }{{BuiltinDirect, "[::1]:53", "ipv4"}, {BuiltinDirect, "127.0.0.1:53", "ipv6"}, {"socks", "remote.invalid:53", "ipv6"}, {BuiltinDirect, "empty.invalid:53", "auto"}} {
		r, err := one.ProbeDiagnosticRequestVersion(t.Context(), tc.name, tc.target, DiagnosticOptions{Protocol: "udp", AddressFamily: tc.family}, 0)
		require.NoError(t, err)
		require.NotEqual(t, "reachable", r.Status)
	}
}

func TestUDPDiagnosticCancellationClosesBlockedSocket(t *testing.T) {
	one := udpDiagnosticEngine(t)
	client, peer := net.Pipe()
	defer peer.Close()
	entered := make(chan struct{})
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) { close(entered); return client, nil }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan DiagnosticResult, 1)
	go func() {
		r, _ := one.ProbeDiagnosticRequestVersion(ctx, BuiltinDirect, "127.0.0.1:53", DiagnosticOptions{Protocol: "udp"}, 0)
		done <- r
	}()
	<-entered
	cancel()
	select {
	case r := <-done:
		require.Equal(t, "canceled", r.Status)
	case <-time.After(time.Second):
		t.Fatal("UDP write ignored cancellation")
	}
}

func TestDiagnosticsRejectMappedAndZonedUnspecifiedTargetsBeforeDialing(t *testing.T) {
	one := udpDiagnosticEngine(t)
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("unspecified diagnostic targets must never open a socket")
		return nil, errors.New("unexpected dial")
	}
	for _, target := range []string{"[::ffff:0.0.0.0]:53", "[::%lo0]:53", "[::ffff:224.0.0.1]:53"} {
		require.Error(t, ValidateDiagnosticTarget(target), target)
		for _, protocol := range []string{"tcp", "udp"} {
			result, err := one.ProbeDiagnosticRequestVersion(t.Context(), BuiltinDirect, target, DiagnosticOptions{Protocol: protocol}, 0)
			require.NoError(t, err)
			require.Equal(t, "failed", result.Status)
			require.Equal(t, "configuration", result.Stage)
		}
	}
	require.NoError(t, ValidateDiagnosticTarget("[fe80::1%lo0]:53"), "link-local servers retain their explicit interface zone")
}

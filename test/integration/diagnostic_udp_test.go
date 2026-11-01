package integration

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func diagnosticDNSReply(raw []byte, offset int) []byte {
	if len(raw) <= offset {
		return nil
	}
	length := 0
	switch raw[offset] {
	case 1:
		length = 7
	case 4:
		length = 19
	case 3:
		if len(raw) < offset+2 {
			return nil
		}
		length = int(raw[offset+1]) + 4
	default:
		return nil
	}
	prefix := offset + length
	if len(raw) < prefix {
		return nil
	}
	query := new(dns.Msg)
	if query.Unpack(raw[prefix:]) != nil {
		return nil
	}
	response := new(dns.Msg)
	response.SetReply(query)
	response.Rcode = dns.RcodeNameError
	packet, _ := response.Pack()
	return append(append([]byte(nil), raw[:prefix]...), packet...)
}

func TestUDPDiagnosticsValidateResponsesOverDirectSOCKS5AndShadowsocks(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := packet.ReadFrom(buffer)
			if err != nil {
				return
			}
			query := new(dns.Msg)
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Rcode = dns.RcodeRefused
			reply.Truncated = true
			data, _ := reply.Pack()
			packet.WriteTo(data, peer)
		}
	}()
	t.Cleanup(func() { packet.Close(); <-done })
	socks, seen := ipv6SOCKSPeerOn(t, "127.0.0.1", func(raw []byte) []byte { return diagnosticDNSReply(raw, 3) })
	ss, ssSeen := ssInteropPeer(t, "chacha20-ietf-poly1305", "udp", false, func(raw []byte) []byte { return diagnosticDNSReply(raw, 0) })
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "socks", URL: socks}, {Name: "ss", URL: "ss://" + url.UserPassword("chacha20-ietf-poly1305", "interop-password").String() + "@" + ss}, {Name: "http", URL: "http://127.0.0.1:1", UDPFallback: "direct"}}
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	require.NoError(t, one.SetConfigVersion(11))
	for _, name := range []string{"direct", "socks", "ss"} {
		t.Run(name, func(t *testing.T) {
			target := "[::1]:53"
			if name == "direct" {
				target = packet.LocalAddr().String()
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			result, err := one.ProbeDiagnosticRequestVersion(ctx, name, target, kone.DiagnosticOptions{Protocol: "udp", DNSType: "AAAA"}, 11)
			require.NoError(t, err)
			require.Equal(t, "reachable", result.Status)
			require.Equal(t, "udp_response", result.Stage)
			require.Equal(t, uint64(11), result.ConfigVersion)
			if name == "direct" {
				require.Equal(t, "REFUSED", result.DNSRCode)
				require.True(t, result.DNSTruncated)
			} else {
				require.Equal(t, "NXDOMAIN", result.DNSRCode)
			}
		})
	}
	select {
	case value := <-seen:
		require.Equal(t, "::1", value.hostname)
	case <-time.After(time.Second):
		t.Fatal("SOCKS peer did not receive the IPv6 destination")
	}
	select {
	case value := <-ssSeen:
		require.Equal(t, byte(4), value[0])
	case <-time.After(time.Second):
		t.Fatal("SS peer did not decrypt the IPv6 destination")
	}
	result, err := one.ProbeDiagnosticRequestVersion(t.Context(), "http", packet.LocalAddr().String(), kone.DiagnosticOptions{Protocol: "udp"}, 11)
	require.NoError(t, err)
	require.Equal(t, "unsupported", result.Status)
	require.Equal(t, "capability", result.Stage)
	require.Empty(t, one.TrafficObserver().Snapshot(kone.TrafficQuery{}).Records, "diagnostics are not business flows")
}

func TestUDPDiagnosticDirectIPv6Loopback(t *testing.T) {
	packet, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback is unavailable")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		n, peer, err := packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		query := new(dns.Msg)
		if query.Unpack(buffer[:n]) != nil {
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		data, _ := reply.Pack()
		packet.WriteTo(data, peer)
	}()
	t.Cleanup(func() { packet.Close(); <-done })
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result, err := one.ProbeDiagnosticRequestVersion(ctx, "direct", packet.LocalAddr().String(), kone.DiagnosticOptions{Protocol: "udp", AddressFamily: "ipv6"}, 0)
	require.NoError(t, err)
	require.Equal(t, "reachable", result.Status)
	require.Equal(t, "NOERROR", result.DNSRCode)
}

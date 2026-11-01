package kone

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestUDPOutboundCapabilitiesAndNoImplicitDial(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		for _, fallback := range []string{"", BuiltinDirect, BuiltinReject} {
			t.Run(scheme+"/"+fallback, func(t *testing.T) {
				p, err := NewOutbounds([]OutboundConfig{{Name: "office", URL: scheme + "://127.0.0.1:8080", UDPFallback: fallback}})
				require.NoError(t, err)
				require.False(t, p.SupportsUDP("office"))
				require.True(t, p.SupportsUDP(BuiltinDirect))
				require.False(t, p.SupportsUDP(BuiltinReject))
				dials := 0
				p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
					dials++
					require.Equal(t, "udp4", network)
					require.Equal(t, "192.0.2.9:443", address)
					return nil, errors.New("dial marker")
				}
				_, err = p.DialUDPContext(context.Background(), "office", "192.0.2.9:443")
				switch fallback {
				case BuiltinDirect:
					require.ErrorContains(t, err, "dial marker")
					require.Equal(t, 1, dials)
				case BuiltinReject:
					require.ErrorIs(t, err, ErrRejected)
					require.Zero(t, dials)
				default:
					require.ErrorIs(t, err, ErrUDPUnsupported)
					require.ErrorContains(t, err, "office")
					require.Zero(t, dials)
				}
				_, err = p.DialUDPContext(context.Background(), BuiltinReject, "192.0.2.9:443")
				require.ErrorIs(t, err, ErrRejected)
				_, err = p.UDPOutbound("missing")
				require.ErrorContains(t, err, "unknown outbound")
			})
		}
	}
}

func TestSOCKS5UDPUsesNativeAssociationWithoutRuntimeFallback(t *testing.T) {
	for _, fallback := range []string{"", BuiltinDirect, BuiltinReject} {
		t.Run(fallback, func(t *testing.T) {
			p, err := NewOutbounds([]OutboundConfig{{Name: "office", URL: "socks5://127.0.0.1:1080", UDPFallback: fallback}})
			require.NoError(t, err)
			require.True(t, p.SupportsUDP("office"))
			target, err := p.UDPOutbound("office")
			require.NoError(t, err)
			require.Equal(t, "office", target)
			dials := 0
			p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				dials++
				require.Equal(t, "tcp", network)
				require.Equal(t, "127.0.0.1:1080", address)
				return nil, errors.New("SOCKS association unavailable")
			}
			_, err = p.DialUDPContext(context.Background(), "office", "private.invalid:443")
			require.ErrorContains(t, err, "SOCKS association unavailable")
			require.Equal(t, 1, dials, "a native association failure must never dial the destination directly")
		})
	}
}

func TestUDPPolicyBeforeResolutionAndSnapshotReload(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	record := one.dnsTable.Set("unresolvable.invalid", "A")
	destination := M.SocksaddrFromNet(&net.UDPAddr{IP: record.IP, Port: 443})
	old := one.policy.Load()
	_, policy, err := one.flows.destination(context.Background(), old, destination, true)
	require.ErrorIs(t, err, ErrUDPUnsupported, "must reject before upstream DNS is needed")
	require.Equal(t, "A", policy)
	require.Nil(t, one.dnsTable.Get(record.Hostname).RealIP)
	one.dnsTable.SetRealIP(record.Hostname, &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Ttl: 60}, A: net.IPv4(192, 0, 2, 9)}}})
	cfg := one.Snapshot().Config
	cfg.Outbounds[0].UDPFallback = BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	allowed := one.policy.Load()
	address, policy, err := one.flows.destination(context.Background(), allowed, destination, true)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.9:443", address)
	require.Equal(t, BuiltinDirect, policy)
	_, _, err = one.flows.destination(context.Background(), old, destination, true)
	require.ErrorIs(t, err, ErrUDPUnsupported)
	cfg.Outbounds[0].UDPFallback = ""
	require.NoError(t, one.Reload(cfg))
	_, _, err = one.flows.destination(context.Background(), one.policy.Load(), destination, true)
	require.ErrorIs(t, err, ErrUDPUnsupported)
	_, _, err = one.flows.destination(context.Background(), allowed, destination, true)
	require.NoError(t, err, "existing sessions retain their allowed snapshot")
	cfg.Rule[0].Outbound = BuiltinReject
	cfg.Outbounds[0].UDPFallback = BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	_, _, err = one.flows.destination(context.Background(), one.policy.Load(), destination, true)
	require.ErrorIs(t, err, ErrRejected)
}

func TestDeniedUDPSessionLogsOutboundAndReleasesResources(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	called := false
	one.flows.NewPacketConnectionEx(context.Background(), bufio.NewPacketConn(conn), M.ParseSocksaddr("192.168.1.2:1234"), M.ParseSocksaddr("192.0.2.9:443"), func(err error) {
		called = true
		require.ErrorIs(t, err, ErrUDPUnsupported)
	})
	require.True(t, called)
	require.Contains(t, output.String(), `"outbound":"A"`)
	require.Contains(t, output.String(), "does not support UDP")
	require.Empty(t, one.flows.active)
	one.flows.workers.Wait()
	require.Error(t, conn.SetReadDeadline(time.Now()))
}

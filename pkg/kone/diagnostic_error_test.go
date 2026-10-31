package kone

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/proxy"
)

type diagnosticTransport struct{}

func (diagnosticTransport) Read([]byte) (int, error)       { return 0, io.EOF }
func (diagnosticTransport) Write(data []byte) (int, error) { return len(data), nil }
func (diagnosticTransport) Close() error                   { return nil }
func (diagnosticTransport) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (diagnosticTransport) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8388}
}
func (diagnosticTransport) SetDeadline(time.Time) error      { return nil }
func (diagnosticTransport) SetReadDeadline(time.Time) error  { return nil }
func (diagnosticTransport) SetWriteDeadline(time.Time) error { return nil }

func TestDiagnosticSeparatesDNSConnectAuthenticationAndPolicy(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := one.DialDiagnostic(ctx, BuiltinDirect, "example.invalid:443")
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, "dns", DiagnosticStage(err))
	_, err = one.DialDiagnostic(context.Background(), BuiltinReject, "192.0.2.1:443")
	require.ErrorIs(t, err, ErrRejected)
	require.Equal(t, "policy", DiagnosticStage(err))
	want := errors.New("connection refused")
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) { return nil, want }
	_, err = one.DialDiagnostic(context.Background(), BuiltinDirect, "192.0.2.1:443")
	require.ErrorIs(t, err, want)
	require.Equal(t, "connect", DiagnosticStage(err))
	require.Equal(t, want.Error(), err.Error())
	_, err = one.DialDiagnostic(context.Background(), "A", "example.com:443")
	require.ErrorIs(t, err, want)
	require.Equal(t, proxy.StageConnect, DiagnosticStage(err))
	for _, target := range []string{"missing-port", "example.com:0"} {
		_, err = one.DialDiagnostic(context.Background(), BuiltinDirect, target)
		require.Equal(t, "configuration", DiagnosticStage(err))
	}
}

func TestShadowsocksDiagnosticTransportSuccessIsNotTargetReachability(t *testing.T) {
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	cfg.Outbounds = []OutboundConfig{{Name: "encrypted", URL: "ss://aes-128-gcm:secret@127.0.0.1:8388"}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	// The fake transport accepts encrypted writes but provides no response from
	// a proxy or target. AEAD stream setup can still return a connection.
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) { return diagnosticTransport{}, nil }
	conn, err := one.DialDiagnostic(context.Background(), "encrypted", "unreachable.invalid:443")
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()
	info := one.DiagnosticTCP("encrypted")
	require.False(t, info.TargetAcknowledged)
	require.Equal(t, proxy.StageTransport, info.Stage)
	require.Equal(t, "proxy_endpoint", info.PeerKind)
	require.True(t, one.DiagnosticTCP(BuiltinDirect).TargetAcknowledged)
	require.False(t, one.DiagnosticTCP(BuiltinReject).TargetAcknowledged)
	require.Equal(t, "configuration", one.DiagnosticTCP("absent").Stage)
	result, err := one.ProbeDiagnostic(context.Background(), "encrypted", "unreachable.invalid:443", false)
	require.NoError(t, err)
	require.Equal(t, "unknown", result.Status)
	require.Equal(t, proxy.StageTransport, result.Stage)
	require.Equal(t, "proxy_endpoint", result.PeerKind)
	result, err = one.ProbeDiagnostic(context.Background(), "encrypted", "unreachable.invalid:443", true)
	require.NoError(t, err)
	require.Equal(t, "failed", result.Status)
	require.Equal(t, "target_tls", result.Stage)
}

func TestDiagnosticUsesPinnedDNSAndRejectsUnappliedVersionsBeforeDialing(t *testing.T) {
	cleanProxyEnv(t)
	var queries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
		w.WriteMsg(reply)
	})
	original := startDNSListeners(t, handler, handler)
	system := original
	reads := 0
	one, err := FromConfig(DefaultConfig(), func(one *One) error {
		one.readSystemDNS = func() ([]string, error) { reads++; return []string{system}, nil }
		one.readSystemDNSContext = func() (DNSSystemContext, error) { return DNSSystemContext{}, nil }
		return nil
	})
	require.NoError(t, err)
	defer one.Close()
	require.NoError(t, one.SetConfigVersion(17))
	system = "127.0.0.1:1" // Represents a later host DNS change, never applied here.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
		close(accepted)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	result, err := one.ProbeDiagnosticVersion(context.Background(), BuiltinDirect, net.JoinHostPort("pinned.example", strconv.Itoa(port)), false, 17)
	require.NoError(t, err)
	require.Equal(t, "reachable", result.Status)
	require.Equal(t, uint64(17), result.ConfigVersion)
	require.Equal(t, "engine_dns_snapshot", result.DNSPath)
	require.Equal(t, 1, reads, "active diagnostics must not re-read a self-guided system DNS configuration")
	require.Equal(t, int32(1), queries.Load())
	<-accepted
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("unapplied revision must not dial even an old same-named outbound")
		return nil, errors.New("unexpected")
	}
	result, err = one.ProbeDiagnosticVersion(context.Background(), BuiltinDirect, "pinned.example:443", false, 18)
	require.NoError(t, err)
	require.Equal(t, "not_applied", result.Status)
	require.Equal(t, "configuration", result.Stage)
	require.Equal(t, int32(1), queries.Load())
}

package integration

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestSystemDNSFinalProxyExpiresKnownDirectAddress(t *testing.T) {
	cfg := systemConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.2:0")
	require.NoError(t, err)
	var oldConnections atomic.Int32
	oldServer := &http.Server{ConnState: func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			oldConnections.Add(1)
		}
	}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "old direct connection") }), ReadHeaderTimeout: time.Second}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); oldServer.Serve(listener) }()
	t.Cleanup(func() { oldServer.Close(); listener.Close(); <-serverDone })
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
	require.NoError(t, err)
	packetDone := make(chan struct{})
	go func() {
		defer close(packetDone)
		buffer := make([]byte, 1024)
		n, source, err := packet.ReadFrom(buffer)
		if err == nil {
			packet.WriteTo(buffer[:n], source)
		}
	}()
	t.Cleanup(func() { packet.Close(); <-packetDone })
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	var changed atomic.Bool
	resolverReady, resolverDone := make(chan struct{}), make(chan struct{})
	resolver := &dns.Server{PacketConn: upstream, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		address := "127.0.0.2"
		if changed.Load() {
			// The refreshed target must not be loopback: local addresses now
			// deliberately bypass proxy rules to prevent recursive capture.
			address = "192.0.2.3"
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(address)}}
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(resolverReady) }}
	go func() { defer close(resolverDone); resolver.ActivateAndServe() }()
	t.Cleanup(func() { resolver.Shutdown(); upstream.Close(); <-resolverDone })
	<-resolverReady
	proxy := localConnectProxy(t, "new proxy connection")
	cfg.DNS.Servers = []string{upstream.LocalAddr().String()}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "office", URL: proxy.URL, UDPFallback: kone.BuiltinDirect}}
	cfg.Rule = []kone.RuleConfig{{Schema: "IP-CIDR", Pattern: "127.0.0.2/32", Outbound: kone.BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}
	one, stop, done := systemStart(t, cfg)
	request := new(dns.Msg)
	request.SetQuestion("rotating-default.example.", dns.TypeA)
	response, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(request, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	fake := response.Answer[0].(*dns.A).A.String()
	_, initial := one.DNSSnapshot()
	require.Nil(t, initial["rotating-default.example"].RealIP, "the initial domain-only proxy decision retains remote DNS")
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	// Explicit UDP fallback learns real DNS data. Its earlier IP rule then
	// selects direct even though the domain-only default remains a proxy.
	seed, err := net.DialTimeout("udp4", net.JoinHostPort(fake, port), 2*time.Second)
	require.NoError(t, err)
	seed.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = seed.Write([]byte("seed"))
	require.NoError(t, err)
	seeded := make([]byte, 4)
	_, err = io.ReadFull(seed, seeded)
	seed.Close()
	require.NoError(t, err)
	require.Equal(t, "seed", string(seeded))
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	get := func(expected string) {
		t.Helper()
		response, err := client.Get("http://" + net.JoinHostPort(fake, port) + "/")
		require.NoError(t, err)
		payload, err := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, err)
		require.Equal(t, expected, string(payload))
	}
	get("old direct connection")
	_, before := one.DNSSnapshot()
	require.Equal(t, "127.0.0.2", before["rotating-default.example"].RealIP.String())
	changed.Store(true)
	time.Sleep(1100 * time.Millisecond)
	get("old direct connection")
	require.Equal(t, int32(1), oldConnections.Load(), "TTL expiry and health probes must preserve the existing TCP connection")
	transport.CloseIdleConnections()
	// Background health may refresh the resolver cache. A new business flow
	// must still replace its expired address evidence and apply the proxy rule.
	get("new proxy connection")
	_, records := one.DNSSnapshot()
	require.Equal(t, fake, records["rotating-default.example"].IP.String())
	require.Equal(t, "192.0.2.3", records["rotating-default.example"].RealIP.String())
	require.Equal(t, "office", records["rotating-default.example"].Proxy)
	transport.CloseIdleConnections()
	stop()
	require.NoError(t, systemWait(t, done))
	noSystemInterface(t, cfg)
}

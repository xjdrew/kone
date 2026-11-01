package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestSystemDNSTCPPortFailureRollsBack(t *testing.T) {
	cfg := systemConfig(t)
	occupied, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	cfg.DNS.ListenPort = uint16(occupied.Addr().(*net.TCPAddr).Port)
	one, err := kone.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := one.Run(context.Background()); err == nil {
		t.Fatal("occupied DNS TCP port did not fail startup")
	}
	if err := one.Close(); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
}

func TestSystemDNSRealTTLRefreshPreservesFakeIP(t *testing.T) {
	cfg := systemConfig(t)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	var changed atomic.Bool
	var queries atomic.Int32
	ready, finished := make(chan struct{}), make(chan struct{})
	resolver := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		target, address := "proxy.cdn.example.", "203.0.113.9"
		if changed.Load() {
			target, address = "direct.cdn.example.", "127.0.0.1"
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: target},
			&dns.A{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(address)},
		}
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(ready) }}
	go func() { defer close(finished); resolver.ActivateAndServe() }()
	t.Cleanup(func() { resolver.Shutdown(); packet.Close(); <-finished })
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("TTL resolver fixture did not start")
	}
	cfg.DNS.Servers = []string{packet.LocalAddr().String()}
	oldProxy := localConnectProxy(t, "old proxy session")
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "new direct session") }))
	t.Cleanup(direct.Close)
	cfg.Outbounds = []kone.OutboundConfig{{Name: "office", URL: oldProxy.URL}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "proxy.cdn.example", Outbound: "office"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	one, stop, done := systemStart(t, cfg)
	request := new(dns.Msg)
	request.SetQuestion("rotating.example.", dns.TypeA)
	address := fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort)
	first, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(request, address)
	require.NoError(t, err)
	require.Len(t, first.Answer, 1)
	fake := first.Answer[0].(*dns.A).A.String()
	require.Contains(t, fake, "10.203.0.")
	_, port, _ := net.SplitHostPort(direct.Listener.Addr().String())
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
	get("old proxy session")
	changed.Store(true)
	// The real DNS TTL is one second while the client's Fake-IP TTL is 600.
	// Exercise actual expiry rather than clearing the engine's private state.
	time.Sleep(1100 * time.Millisecond)
	second, _, err := (&dns.Client{Net: "tcp", Timeout: 2 * time.Second}).Exchange(request, address)
	require.NoError(t, err)
	require.Len(t, second.Answer, 2)
	require.Equal(t, "direct.cdn.example.", second.Answer[0].(*dns.CNAME).Target)
	require.Equal(t, "127.0.0.1", second.Answer[1].(*dns.A).A.String())
	require.Equal(t, int32(2), queries.Load())
	_, records := one.DNSSnapshot()
	require.Equal(t, fake, records["rotating.example"].IP.String())
	require.Equal(t, "127.0.0.1", records["rotating.example"].RealIP.String())
	require.Equal(t, kone.BuiltinDirect, records["rotating.example"].Proxy)
	get("old proxy session")
	transport.CloseIdleConnections()
	get("new direct session")
	transport.CloseIdleConnections()
	stop()
	require.NoError(t, systemWait(t, done))
	noSystemInterface(t, cfg)
}

func TestSystemDNSTransportsAndExclusiveSplitResolver(t *testing.T) {
	cfg := systemConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	var udpCount, tcpCount atomic.Int32
	readyUDP, readyTCP := make(chan struct{}), make(chan struct{})
	udp := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		udpCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Truncated = true
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(readyUDP) }}
	tcp := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		tcpCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		header := dns.RR_Header{Name: request.Question[0].Name, Rrtype: request.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
		if request.Question[0].Qtype == dns.TypeAAAA {
			response.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::53")}}
		} else {
			response.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.0.2.53")}}
		}
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(readyTCP) }}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); udp.ActivateAndServe() }()
	go func() { defer workers.Done(); tcp.ActivateAndServe() }()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown(); workers.Wait() })
	for _, ready := range []chan struct{}{readyUDP, readyTCP} {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("local DNS fixture did not start")
		}
	}
	cfg.DNS.Servers = []string{"127.0.0.1:1"}
	cfg.DNS.Rules = []kone.DNSRouteConfig{{Suffix: "corp", Servers: []string{listener.Addr().String()}}}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "virtual.example", Outbound: "office"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	one, stop, done := systemStart(t, cfg)
	address := fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort)
	for _, transport := range []string{"udp", "tcp"} {
		for _, question := range []struct {
			name string
			kind uint16
		}{{"db.corp.", dns.TypeA}, {"v6.corp.", dns.TypeAAAA}, {"virtual.example.", dns.TypeA}} {
			request := new(dns.Msg)
			request.SetQuestion(question.name, question.kind)
			response, _, err := (&dns.Client{Net: transport, Timeout: 2 * time.Second}).Exchange(request, address)
			if err != nil || response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("%s %s: %v %v", transport, question.name, response, err)
			}
		}
	}
	if udpCount.Load() != 2 || tcpCount.Load() != 2 {
		t.Fatalf("cache/retry counts: UDP=%d TCP=%d", udpCount.Load(), tcpCount.Load())
	}
	events := one.DNSQueries()
	if len(events) != 6 || events[0].Transport != "tcp" {
		t.Fatalf("DNS query history: %+v", events)
	}
	seen := false
	for _, event := range events {
		if event.Upstream == listener.Addr().String() && event.UpstreamTransport == "tcp" && event.Route == "corp" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("history did not record exclusive split upstream and TCP retry")
	}
	stop()
	if err := systemWait(t, done); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
}

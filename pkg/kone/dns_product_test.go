package kone

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func startDNSListeners(t *testing.T, udpHandler, tcpHandler dns.Handler) string {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcp.Close() })
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })
	udpReady, tcpReady := make(chan struct{}), make(chan struct{})
	servers := []*dns.Server{
		{Net: "udp", PacketConn: udp, Handler: udpHandler, NotifyStartedFunc: func() { close(udpReady) }},
		{Net: "tcp", Listener: tcp, Handler: tcpHandler, NotifyStartedFunc: func() { close(tcpReady) }},
	}
	var workers sync.WaitGroup
	for _, server := range servers {
		workers.Add(1)
		go func(server *dns.Server) { defer workers.Done(); server.ActivateAndServe() }(server)
	}
	for _, ready := range []chan struct{}{udpReady, tcpReady} {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("DNS test server did not start")
		}
	}
	t.Cleanup(func() {
		for _, server := range servers {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			server.ShutdownContext(ctx)
			cancel()
		}
		workers.Wait()
	})
	return tcp.Addr().String()
}

func replyA(w dns.ResponseWriter, r *dns.Msg, address string) {
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(address)}}
	w.WriteMsg(reply)
}

func dnsEngine(t *testing.T, upstream string) *One {
	t.Helper()
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, "")
	cfg.DNS.Servers = []string{upstream}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	return one
}

func TestDNSTruncationRetriesTCPAndRecordsActualResolver(t *testing.T) {
	var udpQueries, tcpQueries atomic.Int32
	address := startDNSListeners(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Truncated = true
		w.WriteMsg(reply)
	}), dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { tcpQueries.Add(1); replyA(w, r, "192.0.2.9") }))
	one := dnsEngine(t, address)
	msg, err := one.dns.ResolveContext(context.Background(), "fallback.example")
	require.NoError(t, err)
	require.False(t, msg.Truncated)
	require.Equal(t, "192.0.2.9", msg.Answer[0].(*dns.A).A.String())
	require.Equal(t, int32(1), udpQueries.Load())
	require.Equal(t, int32(1), tcpQueries.Load())
	events := one.DNSQueries()
	require.Len(t, events, 1)
	require.Equal(t, "control", events[0].Scope)
	require.Equal(t, "tcp", events[0].UpstreamTransport)
	require.Equal(t, address, events[0].Upstream)
	require.Equal(t, "NOERROR", events[0].Status)
}

func TestDNSClientUDPAndTCPShareFakeIPPolicy(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	address := startDNSListeners(t, one.dns, one.dns)
	var virtual string
	for _, network := range []string{"udp", "tcp"} {
		request := new(dns.Msg)
		request.SetQuestion("proxy.example.", dns.TypeA)
		response, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(request, address)
		require.NoError(t, err)
		require.Equal(t, dns.RcodeSuccess, response.Rcode)
		ip := response.Answer[0].(*dns.A).A.String()
		if virtual == "" {
			virtual = ip
		} else {
			require.Equal(t, virtual, ip)
		}
	}
	events := one.DNSQueries()
	require.Len(t, events, 2)
	require.Equal(t, "tcp", events[0].Transport)
	require.Equal(t, "udp", events[1].Transport)
	require.Equal(t, []string{virtual}, events[0].VirtualAddresses)
	require.Empty(t, events[0].RealAddresses)
	require.Empty(t, events[0].Upstream)
}

func TestDNSExclusiveSuffixRoutesAndPositiveAnswers(t *testing.T) {
	var publicQueries, privateQueries atomic.Int32
	publicHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		publicQueries.Add(1)
		reply := new(dns.Msg)
		reply.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(reply)
	})
	privateHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { privateQueries.Add(1); replyA(w, r, "192.0.2.53") })
	public := startDNSListeners(t, publicHandler, publicHandler)
	private := startDNSListeners(t, privateHandler, privateHandler)
	one := dnsEngine(t, public)
	one.dns.routes = []DNSRouteConfig{{Suffix: "corp", Servers: []string{private}}, {Suffix: "in-addr.arpa", Servers: []string{private}}}
	for _, name := range []string{"db.corp", "1.2.0.192.in-addr.arpa"} {
		request := new(dns.Msg)
		request.SetQuestion(dns.Fqdn(name), dns.TypeA)
		response, err := one.dns.HandleQuery(context.Background(), request, "udp", "127.0.0.1:1234")
		require.NoError(t, err)
		require.Equal(t, dns.RcodeSuccess, response.Rcode)
		require.Equal(t, private, one.DNSQueries()[0].Upstream)
	}
	require.Zero(t, publicQueries.Load(), "private names must not reach public resolvers")
	require.Equal(t, int32(2), privateQueries.Load())
	// A negative public response cannot mask a positive configured result.
	one.dns.nameservers = []string{public, private}
	request := new(dns.Msg)
	request.SetQuestion("public.example.", dns.TypeA)
	response, err := one.dns.resolve(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, response.Rcode)
	// A failed exclusive resolver never falls back to the default set.
	var fallbackQueries atomic.Int32
	fallbackHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		fallbackQueries.Add(1)
		replyA(w, r, "192.0.2.1")
	})
	one.dns.nameservers = []string{startDNSListeners(t, fallbackHandler, fallbackHandler)}
	one.dns.routes[0].Servers = []string{"127.0.0.1:1"}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	request.SetQuestion("missing.corp.", dns.TypeA)
	_, err = one.dns.resolve(ctx, request)
	require.Error(t, err)
	require.Zero(t, fallbackQueries.Load())
}

func TestDNSResponseCacheAndQueryHistory(t *testing.T) {
	var queries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { queries.Add(1); replyA(w, r, "192.0.2.9") })
	address := startDNSListeners(t, handler, handler)
	one := dnsEngine(t, address)
	request := new(dns.Msg)
	request.SetQuestion("cached.example.", dns.TypeA)
	first, err := one.dns.HandleQuery(context.Background(), request, "udp", "client")
	require.NoError(t, err)
	first.Answer[0].(*dns.A).A[0] = 0
	request.Id++
	second, err := one.dns.HandleQuery(context.Background(), request, "tcp", "client")
	require.NoError(t, err)
	require.Equal(t, request.Id, second.Id)
	require.Equal(t, "192.0.2.9", second.Answer[0].(*dns.A).A.String())
	require.Equal(t, int32(1), queries.Load())
	events := one.DNSQueries()
	require.Len(t, events, 2)
	require.Equal(t, "hit", events[0].Cache)
	require.Empty(t, events[0].AttemptedResolvers, "a cache hit must not imply an upstream exchange")
	require.Empty(t, events[0].UpstreamTransport)
	require.Equal(t, "miss", events[1].Cache)
	events[0].RealAddresses[0] = "changed"
	require.Equal(t, "192.0.2.9", one.DNSQueries()[0].RealAddresses[0])
	require.Positive(t, one.DNSStatus().CacheEntries)
	one.ClearDNSCache()
	require.Zero(t, one.DNSStatus().CacheEntries)
	one.ClearDNSQueries()
	require.Empty(t, one.DNSQueries())
}

func TestDNSCancellationAndConcurrencyLimit(t *testing.T) {
	entered := make(chan struct{})
	var enterOnce sync.Once
	handler := dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) { enterOnce.Do(func() { close(entered) }) })
	address := startDNSListeners(t, handler, handler)
	one := dnsEngine(t, address)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := one.dns.ResolveContext(ctx, "pending.example"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("query was not sent")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation did not close the pending exchange")
	}
	one.dns.pending = make(chan struct{}, 1)
	one.dns.pending <- struct{}{}
	_, err := one.dns.ResolveContext(context.Background(), "capacity.example")
	require.ErrorIs(t, err, ErrDNSBusy)
	<-one.dns.pending
	_, err = one.dns.resolve(context.Background(), nil)
	require.Error(t, err)
}

func TestDNSConfigSplitRoutesAndBounds(t *testing.T) {
	cleanProxyEnv(t)
	valid := "[dns]\n[[dns.rules]]\nsuffix='Corp.'\nservers=['192.0.2.53']\n[[dns.rules]]\nsuffix='.'\nservers=['2001:db8::53']"
	cfg, err := ParseConfig([]byte(valid))
	require.NoError(t, err)
	require.Equal(t, "corp", cfg.DNS.Rules[0].Suffix)
	require.Equal(t, "192.0.2.53:53", cfg.DNS.Rules[0].Servers[0])
	require.Equal(t, ".", cfg.DNS.Rules[1].Suffix)
	for _, bad := range []string{
		"[dns]\nhistory-limit=10001", "[dns]\ncache-limit=10001", "[dns]\nhistory-retention=0",
		"[[dns.rules]]\nsuffix='corp'\nservers=[]", "[[dns.rules]]\nsuffix='bad suffix'\nservers=['192.0.2.53']",
		"[[dns.rules]]\nsuffix='corp'\nservers=['10.192.0.1']", "[[dns.rules]]\nsuffix='corp'\nservers=['hostname']",
		"[[dns.rules]]\nsuffix='corp'\nservers=['192.0.2.53']\n[[dns.rules]]\nsuffix='CORP'\nservers=['192.0.2.54']",
	} {
		_, err := ParseConfig([]byte(bad))
		require.Error(t, err, bad)
	}
}

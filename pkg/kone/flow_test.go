package kone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestFlowDestinationUsesSnapshotAndVirtualAddress(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	h := one.flows
	record := one.dnsTable.Set("example.com", "A")
	one.dnsTable.SetRealIP("example.com", &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Ttl: 60}, A: net.IPv4(192, 0, 2, 10)}}})
	destination := M.SocksaddrFromNet(&net.TCPAddr{IP: record.IP, Port: 443})
	old := one.policy.Load()
	addr, policy, err := h.destination(context.Background(), old, destination, false)
	require.NoError(t, err)
	require.Equal(t, "example.com:443", addr)
	require.Equal(t, "A", policy)
	updated := one.Snapshot().Config
	updated.Rule[0].Outbound = "direct"
	require.NoError(t, one.Reload(updated))
	addr, policy, err = h.destination(context.Background(), one.policy.Load(), destination, false)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.10:443", addr)
	require.Equal(t, "direct", policy)
	_, policy, err = h.destination(context.Background(), old, destination, false)
	require.NoError(t, err)
	require.Equal(t, "A", policy)
	_, _, err = h.destination(context.Background(), old, destination, true)
	require.ErrorIs(t, err, ErrUDPUnsupported)
	addr, policy, err = h.destination(context.Background(), one.policy.Load(), destination, true)
	require.NoError(t, err)
	require.Equal(t, "direct", policy)
	require.Equal(t, "192.0.2.10:443", addr)
	updated.Rule[0].Outbound = "reject"
	require.NoError(t, one.Reload(updated))
	_, _, err = h.destination(context.Background(), one.policy.Load(), destination, true)
	require.ErrorContains(t, err, "rejected")
	for _, addr := range []string{"10.192.0.2:80", "[2001:db8::1]:80"} {
		_, _, err = h.destination(context.Background(), old, M.ParseSocksaddr(addr), false)
		require.Error(t, err)
	}
	require.Equal(t, singtun.ActionAccept, h.JudgeFlow(6, M.ParseSocksaddr("192.168.0.2:4000").AddrPort(), destination.AddrPort(), nil).Action)
}

func TestTransparentTCPFlowRetainsPolicyAndDrains(t *testing.T) {
	cleanProxyEnv(t)
	one, err := FromConfig(parseTestConfig(t, ""))
	require.NoError(t, err)
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer echo.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(conn, conn)
		}
	}()
	client, inbound := tcpPair(t)
	done := make(chan error, 1)
	go one.flows.NewConnectionEx(context.Background(), inbound, M.ParseSocksaddr("192.168.10.20:1234"), M.SocksaddrFromNet(echo.Addr()), func(err error) { done <- err })
	for _, message := range []string{"ping", "pong"} {
		_, err = client.Write([]byte(message))
		require.NoError(t, err)
		data := make([]byte, 4)
		_, err = io.ReadFull(client, data)
		require.NoError(t, err)
		require.Equal(t, message, string(data))
		updated := one.Snapshot().Config
		updated.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "reject"}}
		require.NoError(t, one.Reload(updated))
	}
	one.flows.close()
	one.flows.workers.Wait()
	require.NoError(t, waitRun(t, done))
	<-echoDone
	one.flows.mu.Lock()
	require.Empty(t, one.flows.active)
	one.flows.mu.Unlock()
	late, peer := net.Pipe()
	defer peer.Close()
	one.flows.NewConnectionEx(context.Background(), late, M.Socksaddr{}, M.ParseSocksaddr("127.0.0.1:1"), func(err error) { require.ErrorIs(t, err, net.ErrClosed) })
}

func TestTransparentTCPRejectAndDialFailure(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, policy := range []string{"A", "reject"} {
		cfg := one.Snapshot().Config
		cfg.Rule[0].Outbound = policy
		require.NoError(t, one.Reload(cfg))
		left, right := net.Pipe()
		called := false
		one.flows.NewConnectionEx(ctx, left, M.ParseSocksaddr("192.168.1.2:1234"), M.ParseSocksaddr("203.0.113.1:80"), func(err error) { called = true; require.Error(t, err) })
		require.True(t, called)
		right.Close()
	}
}

type returnPacketConn struct {
	N.PacketConn
	peer M.Socksaddr
}

func (c returnPacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	return c.PacketConn.WritePacket(b, c.peer)
}

func TestTransparentUDPReplyAndConcurrentShutdown(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprint("proxy fallback=", fallback), func(t *testing.T) { testUDPReplyAndShutdown(t, fallback) })
	}
}

func testUDPReplyAndShutdown(t *testing.T, fallback bool) {
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, "")
	if fallback {
		cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:8080", UDPFallback: BuiltinDirect}}
		cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "office"}}
	}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	listen := func() *net.UDPConn {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	echo, client, inbound := listen(), listen(), listen()
	go func() {
		data := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFromUDP(data)
			if err != nil {
				return
			}
			echo.WriteToUDP(data[:n], addr)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	conn := returnPacketConn{bufio.NewPacketConn(inbound), M.SocksaddrFromNet(client.LocalAddr())}
	go one.flows.NewPacketConnectionEx(ctx, conn, M.ParseSocksaddr("192.168.10.20:4000"), M.SocksaddrFromNet(echo.LocalAddr()), func(err error) { done <- err })
	client.SetDeadline(time.Now().Add(2 * time.Second))
	for _, message := range []string{"gateway udp", "existing session"} {
		_, err = client.WriteToUDP([]byte(message), inbound.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
		data := make([]byte, 100)
		n, _, err := client.ReadFromUDP(data)
		require.NoError(t, err)
		require.Equal(t, message, string(data[:n]))
		updated := one.Snapshot().Config
		updated.Rule = []RuleConfig{{Schema: "FINAL", Outbound: BuiltinReject}}
		updated.Outbounds = nil
		require.NoError(t, one.Reload(updated))
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); one.flows.close() }()
	}
	wg.Wait()
	one.flows.workers.Wait()
	require.Error(t, waitRun(t, done))
	one.flows.mu.Lock()
	require.Empty(t, one.flows.active)
	one.flows.mu.Unlock()
	one.flows.NewPacketConnectionEx(ctx, conn, M.Socksaddr{}, M.Socksaddr{}, func(err error) { require.ErrorIs(t, err, net.ErrClosed) })
}

type dnsPacketWriter struct {
	data []byte
	err  error
}

func (w *dnsPacketWriter) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	defer b.Release()
	w.data = append([]byte(nil), b.Bytes()...)
	return w.err
}
func TestStackDNSCallbackPreservesFakeIP(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	writer := new(dnsPacketWriter)
	one.flows.NewDNSPacket([]byte{1}, M.Socksaddr{}, M.Socksaddr{}, writer)
	require.Nil(t, writer.data)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	data, err := query.Pack()
	require.NoError(t, err)
	one.flows.NewDNSPacket(data, M.Socksaddr{}, M.Socksaddr{}, writer)
	reply := new(dns.Msg)
	require.NoError(t, reply.Unpack(writer.data))
	require.Len(t, reply.Answer, 1)
	require.True(t, one.dnsTable.IsLocalIP(reply.Answer[0].(*dns.A).A))
	writer.err = errors.New("closed packet writer")
	one.flows.NewDNSPacket(data, M.Socksaddr{}, M.Socksaddr{}, writer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	one.dns.ctx = ctx
	query.SetQuestion("direct.example.", dns.TypeAAAA)
	data, err = query.Pack()
	require.NoError(t, err)
	one.flows.NewDNSPacket(data, M.Socksaddr{}, M.Socksaddr{}, writer)
	require.NoError(t, reply.Unpack(writer.data))
	require.Equal(t, dns.RcodeServerFailure, reply.Rcode)
}

func TestOutboundInterfaceAndResolver(t *testing.T) {
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, "").Core
	d, err := outboundDialer(cfg, []string{"1.1.1.1:53"})
	require.NoError(t, err)
	require.Nil(t, d.Control)
	cfg.OutboundInterface = "kone-interface-that-does-not-exist"
	_, err = outboundDialer(cfg, []string{"1.1.1.1:53"})
	require.ErrorContains(t, err, "outbound interface")
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iif := range interfaces {
		if iif.Flags&net.FlagUp != 0 {
			cfg.OutboundInterface = iif.Name
			break
		}
	}
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: upstream, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(192, 0, 2, 44)}}
		}
		w.WriteMsg(reply)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	d, err = outboundDialer(cfg, []string{upstream.LocalAddr().String()})
	require.NoError(t, err)
	require.NotNil(t, d.Control)
	require.NotNil(t, d.Resolver)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := d.Resolver.LookupHost(ctx, "gateway.example")
	require.NoError(t, err)
	require.Contains(t, addresses, "192.0.2.44")
	_, err = outboundDialer(cfg, []string{"bad"})
	require.Error(t, err)
}

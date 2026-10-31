package kone

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer ln.Close()
	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	server, err := ln.AcceptTCP()
	require.NoError(t, err)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func TestRelayPreservesTCPHalfClose(t *testing.T) {
	left, a := tcpPair(t)
	right, b := tcpPair(t)
	done := make(chan [2]int64, 1)
	go func() { up, down := relayConnections(a, b); done <- [2]int64{up, down} }()
	_, err := left.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, left.CloseWrite())
	request, err := io.ReadAll(right)
	require.NoError(t, err)
	require.Equal(t, "ping", string(request))
	_, err = right.Write([]byte("pong"))
	require.NoError(t, err)
	require.NoError(t, right.CloseWrite())
	response, err := io.ReadAll(left)
	require.NoError(t, err)
	require.Equal(t, "pong", string(response))
	select {
	case count := <-done:
		require.Equal(t, [2]int64{4, 4}, count)
	case <-time.After(time.Second):
		t.Fatal("copy workers leaked")
	}
}

func TestShutdownCancelsPendingProxyDial(t *testing.T) {
	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxy.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := proxy.Accept()
		if err == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			http.ReadRequest(bufio.NewReader(conn))
			accepted <- conn
		}
	}()
	n, s := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, n, s)
	cfg := one.Snapshot().Config
	cfg.Proxy["A"] = "http://" + proxy.Addr().String()
	cfg.Rule = append(cfg.Rule, RuleConfig{Schema: "FINAL", Proxy: "A"})
	require.NoError(t, one.Reload(cfg))
	probe, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := probe.Addr().(*net.TCPAddr).Port
	defer probe.Close()
	if port == 65535 {
		t.Skip("source port cannot be represented by the exclusive NAT range")
	}
	one.tcpRelay.nat = NewNat(uint16(port), uint16(port+1))
	one.tcpRelay.nat.allocSession(net.IPv4(192, 168, 1, 2), net.IPv4(8, 8, 8, 8), 40000, 80)
	cancel, done := runReady(t, one)
	probe.Close()
	client, err := net.DialTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, s.tcp[0].Addr().(*net.TCPAddr))
	require.NoError(t, err)
	defer client.Close()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("proxy handshake did not start")
	}
	cancel()
	require.NoError(t, waitRun(t, done))
	assertReleased(t, n, s)
	require.Zero(t, one.tcpRelay.nat.count())
	require.Empty(t, one.tcpRelay.active.items)
}

func TestUDPWorkersDrainOnClose(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer echo.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		data := make([]byte, 64)
		n, addr, err := echo.ReadFromUDP(data)
		if err == nil {
			echo.WriteToUDP(data[:n], addr)
		}
	}()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := uint16(client.LocalAddr().(*net.UDPAddr).Port)
	if port == 65535 {
		t.Skip("source port cannot be represented by the exclusive NAT range")
	}
	r := one.udpRelay
	r.nat = NewNat(port, port+1)
	record := one.dnsTable.Set("example.com", "A")
	one.dnsTable.SetRealIP(record.Hostname, &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(127, 0, 0, 1)}}})
	r.nat.allocSession(net.IPv4(192, 168, 1, 2), record.IP, 40000, uint16(echo.LocalAddr().(*net.UDPAddr).Port))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.serve(ctx, local) }()
	_, err = client.WriteToUDP([]byte("udp"), local.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	data := make([]byte, 64)
	n, _, err := client.ReadFromUDP(data)
	require.NoError(t, err)
	require.Equal(t, "udp", string(data[:n]))
	cancel()
	local.Close()
	require.ErrorIs(t, waitRun(t, done), net.ErrClosed)
	r.lock.Lock()
	require.Empty(t, r.tunnels)
	r.lock.Unlock()
	<-echoDone
	r.close()
}

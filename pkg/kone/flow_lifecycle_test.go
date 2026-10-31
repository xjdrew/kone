package kone

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestShutdownCancelsPendingFlowProxyDial(t *testing.T) {
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
	n, sockets := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, n, sockets)
	cfg := one.Snapshot().Config
	setTestOutbound(cfg, "office", "http://"+proxy.Addr().String())
	cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "office"}}
	require.NoError(t, one.Reload(cfg))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() { one.Close() })
	done := make(chan error, 1)
	go func() { done <- one.Run(ctx) }()
	select {
	case <-one.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("engine did not start")
	}
	_, inbound := tcpPair(t)
	flowDone := make(chan error, 1)
	go one.flows.NewConnectionEx(ctx, inbound, M.ParseSocksaddr("192.168.10.20:4000"), M.ParseSocksaddr("192.0.2.9:80"), func(err error) { flowDone <- err })
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("proxy handshake did not start")
	}
	cancel()
	require.NoError(t, waitRun(t, done))
	require.Error(t, waitRun(t, flowDone))
	require.Empty(t, one.flows.active)
	assertReleased(t, n, sockets)
}

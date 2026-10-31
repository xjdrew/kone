package kone

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestProxyEndpointUsesExclusiveSuffixResolver(t *testing.T) {
	var publicQueries, privateQueries atomic.Int32
	public := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) { publicQueries.Add(1); replyA(w, request, "192.0.2.1") })
	private := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) { privateQueries.Add(1); replyA(w, request, "127.0.0.1") })
	publicAddress := startDNSListeners(t, public, public)
	privateAddress := startDNSListeners(t, private, private)
	one := dnsEngine(t, publicAddress)
	one.dns.routes = []DNSRouteConfig{{Suffix: "corp", Servers: []string{privateAddress}}}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	dial := one.endpointDialer(&net.Dialer{Timeout: time.Second})
	conn, err := dial(context.Background(), "tcp4", "proxy.corp:"+port)
	require.NoError(t, err)
	conn.Close()
	require.Equal(t, int32(1), privateQueries.Load())
	require.Zero(t, publicQueries.Load(), "private proxy endpoint must not reach default public DNS")
	require.Equal(t, "control", one.DNSQueries()[0].Scope)
	// Literal and default-hosts endpoints retain their original dialer path.
	for _, target := range []string{listener.Addr().String(), "localhost:" + port} {
		conn, err := dial(context.Background(), "tcp4", target)
		require.NoError(t, err)
		conn.Close()
	}
	require.Equal(t, int32(1), privateQueries.Load())
	require.Zero(t, publicQueries.Load())
}

func TestProxyEndpointScopeFailureDoesNotFallBack(t *testing.T) {
	var queries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeNameError)
		w.WriteMsg(response)
	})
	address := startDNSListeners(t, handler, handler)
	one := dnsEngine(t, "127.0.0.1:1")
	one.dns.routes = []DNSRouteConfig{{Suffix: "corp", Servers: []string{address}}}
	dial := one.endpointDialer(&net.Dialer{Timeout: time.Second})
	_, err := dial(context.Background(), "tcp", "missing.corp:443")
	require.ErrorContains(t, err, "exclusive DNS scope")
	require.Equal(t, int32(1), queries.Load(), "NXDOMAIN does not trigger an unrelated AAAA/public fallback")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = dial(ctx, "tcp", "canceled.corp:443")
	require.ErrorIs(t, err, context.Canceled)
	_, err = dial(context.Background(), "tcp", "missing-port")
	require.Error(t, err)
}

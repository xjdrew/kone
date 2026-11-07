package kone

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyDirectDialerKeepsLocalConnectionsAndPhysicalFallback(t *testing.T) {
	cfg := DefaultConfig()
	baseCalls := 0
	base := &net.Dialer{Control: func(string, string, syscall.RawConn) error { baseCalls++; return net.ErrClosed }}
	dialer, err := policyDirectDialer(base, cfg)
	require.NoError(t, err)
	require.Nil(t, dialer, "legacy profiles retain their existing dialer")
	cfg.Policy.Mode = "direct-first"
	dialer, err = policyDirectDialer(base, cfg)
	require.NoError(t, err)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	connection, err := dialer.DialContext(t.Context(), "tcp4", listener.Addr().String())
	require.NoError(t, err, "local sockets must not be bound to the uplink")
	connection.Close()
	require.Zero(t, baseCalls)
	require.ErrorIs(t, dialer.Control("tcp4", "invalid-address", nil), net.ErrClosed)
	require.Equal(t, 1, baseCalls, "unclassified targets retain the physical uplink control")
	base.Control = nil
	require.NoError(t, dialer.Control("tcp4", "invalid-address", nil))
	snapshot, err := PolicyRouteSnapshot(cfg.Core.Tun)
	require.NoError(t, err)
	require.NotNil(t, snapshot)
}

func TestPolicyRouteIndexUsesSpecificVPNAndLowestMetric(t *testing.T) {
	index := newRouteIndex([]policyRoute{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Interface: 9, Metric: 0},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Interface: 2, Metric: 0},
		{Prefix: netip.MustParsePrefix("10.8.0.0/16"), Interface: 3, Metric: 200},
		{Prefix: netip.MustParsePrefix("10.8.0.0/16"), Interface: 4, Metric: 100},
		{Prefix: netip.MustParsePrefix("fd00::/8"), Interface: 5, Metric: 0},
		{Prefix: netip.MustParsePrefix("fd00:1234::/32"), Interface: 6, Metric: 0},
	})
	for _, test := range []struct {
		address string
		device  int
	}{{"10.8.1.9", 4}, {"10.9.0.1", 2}, {"149.154.167.50", 0}, {"fd00:1234::5", 6}, {"fd00:9999::5", 5}, {"::ffff:10.8.1.9", 4}} {
		require.Equal(t, test.device, index.device(netip.MustParseAddr(test.address)), test.address)
	}
	address := netip.MustParseAddr("fd00:1234::5")
	require.Zero(t, testing.AllocsPerRun(100, func() { index.device(address) }))
}

func TestDirectBusinessDialDoesNotReplaceProxyTransport(t *testing.T) {
	p, err := NewOutbounds([]OutboundConfig{{Name: "proxy", URL: "http://127.0.0.1:7078", UDPFallback: BuiltinDirect}})
	require.NoError(t, err)
	direct, outer := 0, 0
	p.directDial = func(context.Context, string, string) (net.Conn, error) { direct++; return nil, net.ErrClosed }
	p.dial = func(context.Context, string, string) (net.Conn, error) { outer++; return nil, net.ErrClosed }
	_, err = p.DialContext(t.Context(), BuiltinDirect, "10.8.0.1:443")
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = p.DialContext(t.Context(), "proxy", "149.154.167.50:443")
	require.Error(t, err)
	_, err = p.DialUDPContext(t.Context(), "proxy", "10.8.0.1:53")
	require.ErrorIs(t, err, net.ErrClosed)
	require.Equal(t, 2, direct)
	require.Equal(t, 1, outer)
}

func BenchmarkPolicyRouteLookup(b *testing.B) {
	index := newRouteIndex([]policyRoute{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Interface: 2, Metric: 0}, {Prefix: netip.MustParsePrefix("10.8.0.0/16"), Interface: 3, Metric: 0}})
	address := netip.MustParseAddr("10.8.0.1")
	b.ReportAllocs()
	for b.Loop() {
		index.device(address)
	}
}

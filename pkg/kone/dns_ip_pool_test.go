package kone

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSPoolAddressBoundariesAndReuse(t *testing.T) {
	pool := NewDnsIPPool(netip.MustParsePrefix("192.0.2.1/29"))
	pool.reserve(netip.MustParseAddr("192.0.2.2"))
	seen := map[netip.Addr]bool{}
	for range 4 {
		address := pool.Alloc("same hint")
		require.True(t, address.Is4())
		require.True(t, pool.Contains(address))
		require.False(t, seen[address])
		seen[address] = true
	}
	require.False(t, pool.Alloc("full").IsValid())
	for _, text := range []string{"192.0.2.0", "192.0.2.7", "192.0.1.255", "192.0.3.1", "2001:db8::1"} {
		address := netip.MustParseAddr(text)
		require.False(t, pool.Contains(address), text)
		pool.Release(address)
		pool.reserve(address)
	}
	require.False(t, pool.Contains(netip.Addr{}))
	released := netip.MustParseAddr("192.0.2.4")
	pool.Release(released)
	require.Equal(t, released, pool.Alloc("again"))
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("::/64"), netip.MustParsePrefix("192.0.2.1/31")} {
		empty := NewDnsIPPool(prefix)
		require.Zero(t, empty.Capacity())
		require.False(t, empty.Alloc("none").IsValid())
	}
	require.Equal(t, DnsIPPoolMaxSpace, NewDnsIPPool(netip.MustParsePrefix("10.0.0.1/8")).Capacity())
}

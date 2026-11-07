package kone

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPv6DefaultRequiresUsableAddressAndAvoidsOverlaps(t *testing.T) {
	require.Empty(t, selectIPv6Network(false, nil))
	require.Equal(t, "fd7a:203::1/120", selectIPv6Network(true, nil))
	require.Equal(t, "fd7a:203:1::1/120", selectIPv6Network(true, []netip.Prefix{netip.MustParsePrefix("fd7a:203::/64")}))
	require.Empty(t, selectIPv6Network(true, []netip.Prefix{netip.MustParsePrefix("fd7a:203::/32")}))
}

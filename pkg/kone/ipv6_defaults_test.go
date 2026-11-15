package kone

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIPv6DefaultDoesNotRequireANativeIPv6Uplink(t *testing.T) {
	if SupportsIPv6Capture() {
		require.Equal(t, "fd00:10:192::1/64", DefaultIPv6Network())
	} else {
		require.Empty(t, DefaultIPv6Network())
	}
}

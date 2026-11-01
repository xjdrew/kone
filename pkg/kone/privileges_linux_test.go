package kone

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNetworkPrivilegeDependsOnEffectiveCapability(t *testing.T) {
	require.ErrorContains(t, requireNetworkCapability(0), "CAP_NET_ADMIN")
	require.Error(t, requireNetworkCapability(uint32(1)<<unix.CAP_NET_RAW))
	require.NoError(t, requireNetworkCapability(uint32(1)<<unix.CAP_NET_ADMIN))
}

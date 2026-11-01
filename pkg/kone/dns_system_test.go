package kone

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemDNSOptInAndPlatformBoundary(t *testing.T) {
	require.False(t, DefaultConfig().DNS.System, "CLI/TOML defaults must not opt into system changes")
	require.NoError(t, CheckSystemDNS(context.Background(), DNSConfig{}))
	cleanup, err := (systemNetwork{}).ConfigureSystemDNS(context.Background(), nil, CoreConfig{}, DNSConfig{})
	require.NoError(t, err)
	require.Nil(t, cleanup)
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		require.True(t, SupportsSystemDNS())
		return
	}
	require.False(t, SupportsSystemDNS())
	require.ErrorContains(t, CheckSystemDNS(context.Background(), DNSConfig{System: true}), "dns.system")
	cleanup, err = (systemNetwork{}).ConfigureSystemDNS(context.Background(), nil, CoreConfig{}, DNSConfig{System: true})
	require.Error(t, err)
	require.Nil(t, cleanup)
}

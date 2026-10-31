//go:build linux || darwin

package kone

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnixNetworkRollbackCommands(t *testing.T) {
	var calls []string
	fail := false
	n := systemNetwork{run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if fail {
			return nil, errors.New("injected command failure")
		}
		return nil, nil
	}}
	n.routes = unixTestRouteOperations{add: func(context.Context, Device, *net.IPNet) (Cleanup, error) {
		if fail {
			return nil, errors.New("injected route failure")
		}
		calls = append(calls, "kernel route add")
		return func(context.Context) error { calls = append(calls, "kernel route delete"); return nil }, nil
	}}
	cleanup, err := n.Configure(context.Background(), newMemoryDevice(), CoreConfig{Network: "10.192.0.1/16"})
	require.NoError(t, err)
	require.NoError(t, cleanup(context.Background()))
	if runtime.GOOS == "linux" {
		require.Contains(t, calls[0], "ip addr add")
		require.Contains(t, calls[len(calls)-1], "ip addr del")
	} else {
		require.Contains(t, calls[0], "ifconfig")
		require.Contains(t, calls[len(calls)-1], "down")
	}
	_, subnet, _ := net.ParseCIDR("203.0.113.0/24")
	cleanup, err = n.AddRoute(context.Background(), newMemoryDevice(), subnet)
	require.NoError(t, err)
	require.NoError(t, cleanup(context.Background()))
	require.Contains(t, calls[len(calls)-1], "del")
	fail = true
	cleanup, err = n.AddRoute(context.Background(), newMemoryDevice(), subnet)
	require.Error(t, err)
	require.Nil(t, cleanup)
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	require.NotEmpty(t, interfaces)
	_, err = n.Open(context.Background(), CoreConfig{Tun: interfaces[0].Name})
	require.ErrorContains(t, err, "existing interface")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = n.Open(ctx, CoreConfig{})
	require.ErrorIs(t, err, context.Canceled)
}

type unixTestRouteOperations struct {
	add func(context.Context, Device, *net.IPNet) (Cleanup, error)
}

func (r unixTestRouteOperations) AddRoute(ctx context.Context, device Device, prefix *net.IPNet) (Cleanup, error) {
	return r.add(ctx, device, prefix)
}

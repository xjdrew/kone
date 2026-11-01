package kone

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinuxIPv6AddressConfigurationAndPartialRollback(t *testing.T) {
	for _, failIPv6 := range []bool{false, true} {
		var calls [][]string
		marker := errors.New("injected IPv6 address failure")
		network := systemNetwork{run: func(_ context.Context, command string, args ...string) ([]byte, error) {
			require.Equal(t, "ip", command)
			calls = append(calls, append([]string(nil), args...))
			if failIPv6 && len(args) > 3 && args[0] == "-6" && args[2] == "add" {
				return nil, marker
			}
			return nil, nil
		}}
		device := newMemoryDevice()
		cleanup, err := network.Configure(context.Background(), device, CoreConfig{Network: "192.0.2.1/24", IPv6Network: "fd7a:203::1/120"})
		if failIPv6 {
			require.ErrorIs(t, err, marker)
		} else {
			require.NoError(t, err)
		}
		require.NoError(t, cleanup(context.Background()))
		require.Equal(t, []string{"addr", "add", "192.0.2.1/24", "dev", device.Name()}, calls[0])
		require.Equal(t, []string{"-6", "addr", "add", "fd7a:203::1/120", "dev", device.Name(), "nodad"}, calls[1])
		require.Equal(t, []string{"addr", "del", "192.0.2.1/24", "dev", device.Name()}, calls[len(calls)-1])
		if !failIPv6 {
			require.Equal(t, []string{"-6", "addr", "del", "fd7a:203::1/120", "dev", device.Name()}, calls[len(calls)-2])
		}
	}
}

func TestLinuxIPv6RouteCommandsAndPolicyCaptureRollback(t *testing.T) {
	var calls [][]string
	network := systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}}
	_, subnet, _ := net.ParseCIDR("2001:db8::/64")
	cleanup, err := network.AddRoute(context.Background(), newMemoryDevice(), subnet)
	require.NoError(t, err)
	require.NoError(t, cleanup(context.Background()))
	require.Equal(t, "-6", calls[0][0])
	require.Equal(t, "add", calls[0][2])
	require.Equal(t, "del", calls[1][2])
	one := syntheticIPv6Engine(t)
	memory := newMemoryNetwork()
	one.network = memory
	snapshot := *one.policy.Load()
	snapshot.rule = NewRule([]RuleConfig{{Schema: "IP-CIDR6", Pattern: "::/0", Outbound: BuiltinReject}, {Schema: "IP-CIDR6", Pattern: "2001:db8::/64", Outbound: BuiltinReject}}, nil)
	one.policy.Store(&snapshot)
	var undo undoStack
	require.NoError(t, one.addIPv6Routes(context.Background(), memory.device, CoreConfig{IPv6Network: "fd7a:203::1/120", AutoRoute6: true}, &undo))
	require.Len(t, memory.routes, 3, "auto-route6 and default CIDR6 must not duplicate the /1 routes")
	require.NoError(t, undo.restore(context.Background()))
	require.Empty(t, memory.routes)
}

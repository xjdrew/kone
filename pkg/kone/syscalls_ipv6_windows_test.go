package kone

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const windowsIPv6Fixture = `{"Index":42,"GUID":"{12345678-1234-1234-1234-123456789abc}","MTU":1400,"Metric":25,"AutomaticMetric":"Enabled","DHCP":"Enabled","RouterDiscovery":"Enabled","DadTransmits":1,"Managed":"Enabled","Stateful":"Enabled","Addresses":[{"IPAddress":"fe80::1","PrefixLength":64}]}`

func windowsCommandParams(t *testing.T, script string) map[string]any {
	t.Helper()
	_, encoded, found := strings.Cut(script, "FromBase64String('")
	require.True(t, found)
	encoded, _, _ = strings.Cut(encoded, "')")
	data, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	var params map[string]any
	require.NoError(t, json.Unmarshal(data, &params))
	return params
}

func TestWindowsIPv6SnapshotIsValidatedBeforeMutation(t *testing.T) {
	for _, snapshot := range []string{
		windowsIPv6Fixture,
		"invalid",
		`{}`,
		strings.Replace(windowsIPv6Fixture, `"MTU":1400`, `"MTU":1200`, 1),
		strings.Replace(windowsIPv6Fixture, `"DadTransmits":1`, `"DadTransmits":-1`, 1),
		strings.Replace(windowsIPv6Fixture, `"Enabled"`, `"unknown"`, 1),
		strings.Replace(windowsIPv6Fixture, "fe80::1", "fd7a:204::1", 1),
	} {
		calls := 0
		network := systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls++
			script := decodePowerShell(t, args)
			require.Contains(t, script, "-AddressFamily IPv6")
			require.NotContains(t, script, "Set-NetIPInterface")
			return []byte(snapshot), nil
		}}
		settings, err := network.readIPv6Settings(context.Background(), newMemoryDevice(), CoreConfig{IPv6Network: "fd7a:204::1/120"})
		if snapshot == windowsIPv6Fixture {
			require.NoError(t, err)
			require.Equal(t, 42, settings.Index)
		} else {
			require.Error(t, err)
		}
		require.Equal(t, 1, calls)
	}
	network := systemNetwork{run: func(context.Context, string, ...string) ([]byte, error) { return nil, context.Canceled }}
	_, err := network.readIPv6Settings(context.Background(), newMemoryDevice(), CoreConfig{IPv6Network: "fd7a:204::1/120"})
	require.ErrorIs(t, err, context.Canceled)
}

func TestWindowsIPv6ConfigurationRollsBackAttemptedChanges(t *testing.T) {
	var old windowsIPv6Settings
	require.NoError(t, json.Unmarshal([]byte(windowsIPv6Fixture), &old))
	for failAt := 0; failAt <= 4; failAt++ {
		calls, restores := 0, 0
		failure := errors.New("injected IPv6 setting failure")
		network := systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			script := decodePowerShell(t, args)
			require.Contains(t, script, "owned IPv6 interface identity changed")
			require.Contains(t, script, "-AddressFamily IPv6")
			require.NotContains(t, script, "-AddressFamily IPv4")
			if strings.Contains(script, "external IPv6") {
				restores++
				params := windowsCommandParams(t, script)
				require.Len(t, params["Actions"], calls, "every attempted write remains in the reverse-order restoration batch")
				require.Contains(t, script, "catch { $koneRestoreErrors.Add")
				return nil, nil
			}
			calls++
			if calls == failAt {
				return nil, failure
			}
			return nil, nil
		}}
		undo, err := network.configureIPv6(context.Background(), newMemoryDevice(), CoreConfig{IPv6Network: "fd7a:204::1/120"}, old)
		if failAt > 0 {
			require.ErrorIs(t, err, failure)
			require.Equal(t, failAt, calls)
		} else {
			require.NoError(t, err)
			require.Equal(t, 4, calls)
		}
		require.NotNil(t, undo)
		require.NoError(t, undo(context.Background()))
		require.Equal(t, 1, restores, "all attempted IPv6 writes restore in one PowerShell process")
	}
}

func TestWindowsIPv6RouteOwnershipAndOnLinkNextHop(t *testing.T) {
	for _, reply := range []string{
		`{"Index":42,"GUID":"{12345678-1234-1234-1234-123456789abc}","Count":0}`,
		`{"Index":42,"GUID":"{12345678-1234-1234-1234-123456789abc}","Count":1}`,
		`{}`,
		`invalid`,
	} {
		var scripts []string
		network := systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			last := decodePowerShell(t, args)
			scripts = append(scripts, last)
			params := windowsCommandParams(t, last)
			require.Equal(t, "::", params["Gateway"])
			require.Contains(t, last, "-AddressFamily IPv6")
			if len(scripts) == 1 {
				return []byte(reply), nil
			}
			if strings.Contains(last, "New-NetRoute") {
				return nil, context.DeadlineExceeded
			}
			return nil, nil
		}}
		_, subnet, _ := net.ParseCIDR("fd7a:205::/120")
		undo, err := network.AddRoute(context.Background(), newMemoryDevice(), subnet)
		require.Error(t, err)
		if strings.Contains(reply, `"Count":0`) {
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.NotNil(t, undo)
			require.NoError(t, undo(context.Background()))
			require.Len(t, scripts, 3)
			require.Contains(t, scripts[2], "owned IPv6 interface identity changed")
			require.Contains(t, scripts[2], "-NextHop $p.Gateway")
		} else {
			require.Nil(t, undo)
			require.Len(t, scripts, 1, "pre-existing or unknown routes cannot be removed")
		}
	}
}

func TestWindowsIPv6AutoRouteIsCommandTestOnly(t *testing.T) {
	one := syntheticIPv6Engine(t)
	created := []string{}
	one.network = systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		script := decodePowerShell(t, args)
		params := windowsCommandParams(t, script)
		require.Equal(t, "::", params["Gateway"])
		if strings.Contains(script, "Count=@(") {
			return []byte(`{"Index":42,"GUID":"{12345678-1234-1234-1234-123456789abc}","Count":0}`), nil
		}
		if strings.Contains(script, "New-NetRoute") {
			created = append(created, params["Prefix"].(string))
		}
		return nil, nil
	}}
	cfg := one.Snapshot().Config.Core
	cfg.AutoRoute6 = true
	var undo undoStack
	require.NoError(t, one.addIPv6Routes(context.Background(), newMemoryDevice(), cfg, &undo))
	require.Equal(t, []string{"::/1", "8000::/1"}, created)
	require.NoError(t, undo.restore(context.Background()))
}

func TestWindowsIPv6FirewallIncludesOnlyOwnedLocalAddresses(t *testing.T) {
	calls := 0
	network := systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls++
		script := decodePowerShell(t, args)
		params := windowsCommandParams(t, script)
		require.Equal(t, []any{"10.204.0.1", "fd7a:204::1"}, params["IP"])
		if calls == 1 {
			return []byte("0"), nil
		}
		if calls == 2 {
			require.Contains(t, script, "-LocalAddress $p.IP")
		}
		return nil, nil
	}}
	undo, err := network.PrepareStack(context.Background(), CoreConfig{Network: "10.204.0.1/24", IPv6Network: "fd7a:204::1/120"})
	require.NoError(t, err)
	require.NoError(t, undo(context.Background()))
}

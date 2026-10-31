//go:build darwin

package kone

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDarwinSystemDNSSelectionDiagnosticIsExplicitAndBounded(t *testing.T) {
	err := darwinSelectionError([]byte(strings.Repeat("private-resolver", 2000)), []byte(strings.Repeat("private-profile", 2000)))
	require.NotContains(t, err.Error(), "private")
	encoded, marshalErr := json.Marshal(err)
	require.NoError(t, marshalErr)
	require.NotContains(t, string(encoded), "private")
	snapshot := err.(interface{ SystemDNSDiagnostic() string }).SystemDNSDiagnostic()
	require.Contains(t, snapshot, "private-resolver")
	require.Less(t, len(snapshot), 10400)
}

func TestDarwinOwnedSystemDNSSessionDeath(t *testing.T) {
	if os.Getenv("KONE_DARWIN_DNS_SYSTEM_TEST") != "1" {
		t.Skip("requires the disposable privileged macOS DNS acceptance runner")
	}
	require.Equal(t, 0, os.Geteuid())
	require.True(t, SupportsSystemDNS(), "macOS system DNS support must be enabled")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	original, err := readDNSSystemContext()
	require.NoError(t, err)
	var server netip.AddrPort
	for _, value := range original.DefaultServers {
		if candidate, err := netip.ParseAddrPort(value); err == nil && candidate.Addr().Is4() {
			server = candidate
			break
		}
	}
	require.True(t, server.IsValid(), "an original IPv4 DNS endpoint is needed to keep resolver behavior unchanged")
	network := systemNetwork{run: runCommand}
	core := DefaultConfig().Core
	core.Network = "198.18.119.1/24"
	core.AutoRoute = false
	device, err := network.Open(ctx, core) // creates an exclusive utun only; no interface/route configuration
	require.NoError(t, err)
	defer device.Close()
	id := "d15ea5ed-1234-1234-1234-" + fmtScopedPID(os.Getpid())
	hooks := newDarwinScopedDNSHooks()
	originalLaunch := hooks.launch
	var killOwned func() error
	hooks.launch = func(script string) (scopedDNSProcess, error) {
		process, err := originalLaunch(script)
		if err == nil {
			killOwned = process.kill
		}
		return process, err
	}
	cleanup, failures, err := configureScopedDNS(ctx, hooks, id, device.Name(), server.Addr(), server.Port(), func() error {
		name, err := device.(*singDevice).Tun.Name()
		if err == nil && name != device.Name() {
			return os.ErrNotExist
		}
		return err
	})
	if cleanup != nil {
		defer func() {
			budget, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			require.NoError(t, cleanup(budget))
		}()
	}
	require.NoError(t, err)
	require.NotNil(t, killOwned)
	require.NoError(t, killOwned()) // exact exec.Cmd process handle, never a name/PID search
	select {
	case failure, open := <-failures:
		require.True(t, open)
		require.Error(t, failure)
	case <-ctx.Done():
		t.Fatal("scutil session death did not notify the lifecycle")
	}
	key := "State:/Network/Service/" + id + "/DNS"
	require.Eventually(t, func() bool {
		data, err := hooks.read(ctx, key)
		if err != nil {
			return false
		}
		_, exists, err := parseScopedDNSProfile(data)
		return err == nil && !exists
	}, 5*time.Second, 25*time.Millisecond, "configd must automatically remove a dead session's temporary key")
	require.Eventually(t, func() bool {
		after, err := readDNSSystemContext()
		return err == nil && reflect.DeepEqual(original.DefaultServers, after.DefaultServers) && reflect.DeepEqual(original.SearchDomains, after.SearchDomains)
	}, 5*time.Second, 50*time.Millisecond, "original DNS selection/search domains must return after session death")
}

func fmtScopedPID(pid int) string {
	const digits = "0123456789abcdef"
	buffer := [12]byte{}
	for index := len(buffer) - 1; index >= 0; index-- {
		buffer[index] = digits[pid&15]
		pid >>= 4
	}
	return string(buffer[:])
}

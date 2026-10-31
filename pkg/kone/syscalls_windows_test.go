package kone

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func decodePowerShell(t *testing.T, args []string) string {
	t.Helper()
	require.Equal(t, []string{"-NoProfile", "-NonInteractive", "-EncodedCommand"}, args[:3])
	data, err := base64.StdEncoding.DecodeString(args[3])
	require.NoError(t, err)
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(words))
}

func TestWindowsStackFirewallOwnership(t *testing.T) {
	for _, existing := range []bool{false, true} {
		calls := 0
		n := systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls++
			script := decodePowerShell(t, args)
			require.Contains(t, script, "$_.DisplayName -eq $p.Rule")
			if calls == 1 {
				if existing {
					return []byte("1"), nil
				}
				return []byte("0"), nil
			}
			require.Contains(t, script, "Remove-NetFirewallRule")
			return nil, nil
		}}
		undo, err := n.PrepareStack(context.Background())
		require.NoError(t, err)
		if existing {
			require.Nil(t, undo)
		} else {
			require.NoError(t, undo(context.Background()))
		}
	}
	for _, reply := range []string{"invalid", "0"} {
		n := systemNetwork{run: func(context.Context, string, ...string) ([]byte, error) {
			if reply == "0" {
				return nil, errors.New("access denied")
			}
			return []byte(reply), nil
		}}
		undo, err := n.PrepareStack(context.Background())
		require.Error(t, err)
		require.Nil(t, undo)
	}
}

func TestWindowsConfigurationRollback(t *testing.T) {
	for failAt := 0; failAt <= 5; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			var calls []string
			count := 0
			n := systemNetwork{run: func(_ context.Context, name string, args ...string) ([]byte, error) {
				require.Equal(t, "powershell", name)
				script := decodePowerShell(t, args)
				if strings.Contains(script, "$key=") {
					return []byte(`{"Index":42,"MTU":1400,"Metric":25,"AutomaticMetric":"Enabled","DHCP":"Enabled","StaticDNS":true,"DNS":["1.1.1.1"],"Addresses":[{"IPAddress":"192.168.1.10","PrefixLength":24}]}`), nil
				}
				count++
				calls = append(calls, script)
				if count == failAt {
					return nil, errors.New("injected Windows command failure")
				}
				return nil, nil
			}}
			cleanup, err := n.Configure(context.Background(), newMemoryDevice(), CoreConfig{Network: "10.192.0.1/16"})
			if failAt > 0 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NotNil(t, cleanup)
			require.NoError(t, cleanup(context.Background()))
			joined := strings.Join(calls, "\n")
			if failAt != 1 {
				require.Contains(t, joined, "if($p.Auto -eq 'Enabled')")
			}
			require.NotContains(t, joined, "Remove-NetRoute")
			require.Contains(t, joined, "-NlMtuBytes $p.OldMTU")
			if failAt == 0 {
				require.Contains(t, joined, "-ResetServerAddresses")
				require.Contains(t, joined, "-Dhcp Enabled")
				require.Contains(t, joined, "Get-NetIPAddress -InterfaceIndex $p.Index -IPAddress $p.IP -PrefixLength $p.Prefix")
			}
		})
	}
}

func TestWindowsSnapshotErrorsDoNotMutate(t *testing.T) {
	for _, data := range []string{`not-json`, `{}`, `{"Index":1,"MTU":1500,"Metric":1,"AutomaticMetric":"Enabled","DHCP":"Disabled","Addresses":[{"IPAddress":"10.192.0.1"}]}`} {
		calls := 0
		n := systemNetwork{run: func(context.Context, string, ...string) ([]byte, error) { calls++; return []byte(data), nil }}
		undo, err := n.Configure(context.Background(), newMemoryDevice(), CoreConfig{Network: "10.192.0.1/16"})
		require.Error(t, err)
		require.Nil(t, undo)
		require.Equal(t, 1, calls)
	}
}

func TestNewWintunWithoutIPv4AddressCanBeConfigured(t *testing.T) {
	calls := 0
	configuredL3 := false
	n := systemNetwork{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls++
		script := decodePowerShell(t, args)
		if calls == 1 {
			require.Contains(t, script, "CmdletizationQuery_NotFound*")
			require.Contains(t, script, "-ErrorAction Stop")
			return []byte(`{"Index":42,"MTU":1500,"Metric":0,"AutomaticMetric":"Enabled","DHCP":"Disabled","StaticDNS":false,"DNS":[],"Addresses":[]}`), nil
		}
		if strings.Contains(script, "-Forwarding Enabled") {
			configuredL3 = true
			require.Contains(t, script, "-DadTransmits 0")
		}
		return nil, nil
	}}
	device := &singDevice{Tun: &stubTun{memoryDevice: newMemoryDevice()}, name: "kone-test"}
	defer device.Close()
	undo, err := n.Configure(context.Background(), device, CoreConfig{Network: "10.192.0.1/16"})
	require.NoError(t, err)
	require.NoError(t, undo(context.Background()))
	require.Equal(t, 10, calls)
	require.True(t, configuredL3)
}

func TestWindowsRouteOwnershipAndTimeout(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("203.0.113.0/24")
	for _, existing := range []bool{false, true} {
		var scripts []string
		n := systemNetwork{gateway: "10.192.0.0", run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			script := decodePowerShell(t, args)
			scripts = append(scripts, script)
			if strings.Contains(script, ".Count | ConvertTo-Json") {
				if existing {
					return []byte("1"), nil
				}
				return []byte("0"), nil
			}
			if strings.Contains(script, "New-NetRoute") {
				return nil, context.DeadlineExceeded
			}
			return nil, nil
		}}
		undo, err := n.AddRoute(context.Background(), newMemoryDevice(), subnet)
		require.Error(t, err)
		if existing {
			require.Nil(t, undo)
			require.Len(t, scripts, 1)
		} else {
			require.NotNil(t, undo)
			require.NoError(t, undo(context.Background()))
			require.Contains(t, scripts[2], "-NextHop $p.Gateway")
			require.Contains(t, scripts[2], "Remove-NetRoute -Confirm:$false")
		}
	}
}

func TestReadWindowsSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := systemNetwork{run: runCommand}
	data, err := n.powershell(ctx, `Get-NetAdapter | Where-Object { Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue } | Select-Object -First 1 -ExpandProperty Name | ConvertTo-Json`, nil)
	require.NoError(t, err)
	var name string
	require.NoError(t, json.Unmarshal(data, &name))
	require.NotEmpty(t, name)
	data, err = n.powershell(ctx, readWindowsSettings, map[string]any{"Name": name})
	require.NoError(t, err)
	var snapshot windowsSettings
	require.NoError(t, json.Unmarshal(data, &snapshot))
	require.Positive(t, snapshot.Index)
	require.Positive(t, snapshot.MTU)
	require.Contains(t, []string{"Enabled", "Disabled"}, snapshot.DHCP)
	require.Contains(t, []string{"Enabled", "Disabled"}, snapshot.AutomaticMetric)
}

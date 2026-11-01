package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func requireWindowsDNSRunner(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("KONE_WINDOWS_SYSTEM_TEST") != "1" {
		t.Skip("requires an explicitly enabled disposable administrator GitHub runner")
	}
}

func windowsDNSNativeScript(t *testing.T, script string, params any) string {
	t.Helper()
	data, err := json.Marshal(params)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := "$ErrorActionPreference='Stop'; $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(data) + "')) | ConvertFrom-Json; " + script
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", command).CombinedOutput()
	require.NoError(t, err, "%s", out)
	return strings.TrimSpace(string(out))
}

func windowsDNSPhysicalSnapshot(t *testing.T) string {
	return windowsDNSNativeScript(t, `[pscustomobject]@{
dns=@(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses);
interfaces=@(Get-NetIPInterface | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,AutomaticMetric,InterfaceMetric);
defaults=@(Get-NetRoute | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')} | Sort-Object InterfaceIndex,DestinationPrefix | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
} | ConvertTo-Json -Depth 6 -Compress`, nil)
}

func windowsDNSNativeConfig(t *testing.T, stack string) *kone.KoneConfig {
	t.Helper()
	cfg, err := kone.ParseConfig([]byte(fmt.Sprintf(`[core]
tun="kone-dns-%d"
stack="%s"
network="10.207.0.1/24"
[dns]
system=true
listen-port=53
servers=["1.1.1.1"]
[[outbounds]]
name="Fixture"
url="http://127.0.0.1:9"
[[rules]]
type="FINAL"
outbound="Fixture"
`, os.Getpid(), stack)))
	require.NoError(t, err)
	return cfg
}

func startWindowsDNSCapture(t *testing.T, cfg *kone.KoneConfig) (*kone.One, <-chan error, context.CancelFunc) {
	t.Helper()
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	done := make(chan error, 1)
	go func() { done <- one.Run(ctx) }()
	t.Cleanup(func() { cancel(); _ = one.Close() })
	select {
	case <-one.Ready():
	case err := <-done:
		t.Fatalf("Windows system DNS startup: %v", err)
	case <-ctx.Done():
		t.Fatal("Windows system DNS startup timed out")
	}
	return one, done, cancel
}

func windowsDNSLease(t *testing.T) kone.SystemDNSRecoveryEntry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	entries, err := kone.InspectSystemDNSRecovery(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	return entries[0]
}

func windowsDNSWaitDeviceAbsent(t *testing.T, name string) {
	t.Helper()
	require.Eventually(t, func() bool { _, err := net.InterfaceByName(name); return err != nil }, 15*time.Second, 50*time.Millisecond)
}

func recoverWindowsDNSLease(t *testing.T, id string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, kone.RecoverSystemDNS(ctx, id))
	entries, err := kone.InspectSystemDNSRecovery(ctx)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestSystemWindowsDNS(t *testing.T) {
	requireWindowsDNSRunner(t)
	for _, stack := range kone.SupportedStacks() {
		t.Run(stack, func(t *testing.T) {
			t.Run("resolver_restore", func(t *testing.T) {
				before := windowsDNSPhysicalSnapshot(t)
				// A more-specific private/VPN rule must survive the root lease.
				private := windowsDNSNativeScript(t, `$r=Add-DnsClientNrptRule -Namespace '.kone-private.invalid' -NameServers '192.0.2.53' -DisplayName 'KONE native private fixture' -PassThru; [string]$r.Name`, nil)
				t.Cleanup(func() {
					windowsDNSNativeScript(t, `Remove-DnsClientNrptRule -Name $p.Name -Force`, map[string]string{"Name": private})
				})
				one, done, cancel := startWindowsDNSCapture(t, windowsDNSNativeConfig(t, stack))
				lease := windowsDNSLease(t)
				require.Equal(t, "active", lease.Status)
				require.False(t, lease.CanRecover)
				ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
				require.Error(t, kone.RecoverSystemDNS(ctx, lease.ID), "a second process must not remove a live owner's lease")
				stop()
				// Resolve-DnsName uses the Windows DNS API and NRPT; nslookup and
				// an explicit -Server would bypass precisely the feature under test.
				answer := windowsDNSNativeScript(t, `Resolve-DnsName -Name $p.Name -Type A -DnsOnly -NoHostsFile | Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress`, map[string]string{"Name": fmt.Sprintf("%d.kone-resolver.invalid", time.Now().UnixNano())})
				require.True(t, strings.HasPrefix(answer, "10.207.0."), "system resolver did not reach KONE Fake-IP: %s", answer)
				windowsDNSNativeScript(t, `$r=Get-DnsClientNrptRule -Name $p.Name; if([string]$r.NameServers -cne '192.0.2.53'){throw 'private policy changed'}`, map[string]string{"Name": private})
				cancel()
				require.NoError(t, <-done)
				require.NoError(t, one.Close())
				windowsDNSWaitDeviceAbsent(t, lease.DeviceName)
				entries, err := kone.InspectSystemDNSRecovery(context.Background())
				require.NoError(t, err)
				require.Empty(t, entries)
				require.Equal(t, before, windowsDNSPhysicalSnapshot(t), "physical DNS, metrics or default routes changed")
			})
			t.Run("startup_conflict", func(t *testing.T) {
				before := windowsDNSPhysicalSnapshot(t)
				foreign := windowsDNSNativeScript(t, `$r=Add-DnsClientNrptRule -Namespace '.' -NameServers '192.0.2.54' -DisplayName 'KONE native external owner fixture' -PassThru; [string]$r.Name`, nil)
				t.Cleanup(func() {
					windowsDNSNativeScript(t, `Remove-DnsClientNrptRule -Name $p.Name -Force`, map[string]string{"Name": foreign})
				})
				one, err := kone.FromConfig(windowsDNSNativeConfig(t, stack))
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				require.Error(t, one.Run(ctx), "existing root policy must block startup without replacement")
				require.NoError(t, one.Close())
				windowsDNSNativeScript(t, `$r=Get-DnsClientNrptRule -Name $p.Name; if([string]$r.NameServers -cne '192.0.2.54'){throw 'external root policy changed'}`, map[string]string{"Name": foreign})
				require.Equal(t, before, windowsDNSPhysicalSnapshot(t))
			})
			t.Run("external_change", func(t *testing.T) {
				_, done, _ := startWindowsDNSCapture(t, windowsDNSNativeConfig(t, stack))
				lease := windowsDNSLease(t)
				original := windowsDNSNativeScript(t, `[string](Get-DnsClientNrptRule -Name $p.Name).Comment`, map[string]string{"Name": lease.RuleName})
				t.Cleanup(func() {
					windowsDNSNativeScript(t, `Set-DnsClientNrptRule -Name $p.Name -Comment $p.Comment`, map[string]string{"Name": lease.RuleName, "Comment": original})
					recoverWindowsDNSLease(t, lease.ID)
				})
				windowsDNSNativeScript(t, `Set-DnsClientNrptRule -Name $p.Name -Comment 'changed by external fixture'`, map[string]string{"Name": lease.RuleName})
				select {
				case err := <-done:
					require.Error(t, err)
				case <-time.After(30 * time.Second):
					t.Fatal("lost NRPT ownership did not stop capture")
				}
				entry := windowsDNSLease(t)
				require.Equal(t, "changed", entry.Status)
				require.False(t, entry.CanRecover)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				require.Error(t, kone.RecoverSystemDNS(ctx, lease.ID))
				comment := windowsDNSNativeScript(t, `[string](Get-DnsClientNrptRule -Name $p.Name).Comment`, map[string]string{"Name": lease.RuleName})
				require.Equal(t, "changed by external fixture", comment)
			})
			for _, pending := range []bool{false, true} {
				t.Run(fmt.Sprintf("crash_pending=%t", pending), func(t *testing.T) {
					windowsDNSCrashRecovery(t, stack, pending)
				})
			}
		})
	}
}

func windowsDNSCrashRecovery(t *testing.T, stack string, pending bool) {
	before := windowsDNSPhysicalSnapshot(t)
	ready := filepath.Join(t.TempDir(), "dns-ready")
	config, err := toml.Marshal(windowsDNSNativeConfig(t, stack))
	require.NoError(t, err)
	child := exec.Command(os.Args[0], "-test.run=^TestSystemWindowsDNSChild$", "-test.v")
	child.Env = append(os.Environ(), "KONE_DNS_CHILD_CONFIG="+base64.StdEncoding.EncodeToString(config), "KONE_DNS_CHILD_READY="+ready)
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	require.NoError(t, child.Start())
	finished := make(chan error, 1)
	go func() { finished <- child.Wait() }()
	t.Cleanup(func() { _ = child.Process.Kill() })
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case err := <-finished:
			t.Fatalf("DNS child exited before readiness: %v\n%s", err, output.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS child startup timed out")
		}
	}
	lease := windowsDNSLease(t)
	// Kill the lease worker as well as its helper to exercise durable recovery,
	// rather than relying solely on the normal stdin-EOF rollback path. Clearing
	// RuleName simulates the precise crash window after Add but before its ACK.
	windowsDNSNativeScript(t, `$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Kone\DNSLeases\'+$p.ID,$true); try {
$r=([string]$key.GetValue('Record'))|ConvertFrom-Json;
if($p.Pending){$r.RuleName='';$key.SetValue('Record',($r|ConvertTo-Json -Compress));$key.Flush()};
$w=Get-Process -Id $r.WorkerPID; if($w.StartTime.ToUniversalTime().Ticks -ne $r.WorkerStart){throw 'worker identity changed'};
Stop-Process -Id $r.WorkerPID -Force;
} finally {$key.Dispose()}`, map[string]any{"ID": lease.ID, "Pending": pending})
	_ = child.Process.Kill()
	select {
	case <-finished:
	case <-time.After(15 * time.Second):
		t.Fatal("DNS helper did not exit")
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(ready); err != nil {
			t.Fatal("readiness evidence disappeared")
		}
		entry := windowsDNSLease(t)
		if entry.CanRecover {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("crashed lease is not recoverable: %+v", entry)
		}
	}
	recoverWindowsDNSLease(t, lease.ID)
	windowsDNSWaitDeviceAbsent(t, lease.DeviceName)
	require.Equal(t, before, windowsDNSPhysicalSnapshot(t), "crash recovery changed physical DNS/metrics/default routes")
}

func TestSystemWindowsDNSChild(t *testing.T) {
	if os.Getenv("KONE_DNS_CHILD_CONFIG") == "" {
		t.Skip("subprocess fixture only")
	}
	requireWindowsDNSRunner(t)
	data, err := base64.StdEncoding.DecodeString(os.Getenv("KONE_DNS_CHILD_CONFIG"))
	require.NoError(t, err)
	cfg, err := kone.ParseConfig(data)
	require.NoError(t, err)
	_, done, _ := startWindowsDNSCapture(t, cfg)
	require.NoError(t, os.WriteFile(os.Getenv("KONE_DNS_CHILD_READY"), []byte("ready"), 0600))
	t.Fatal(<-done)
}

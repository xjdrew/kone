package desktop

import (
	"bytes"
	"context"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestDarwinPrivateSocketOwnershipAndPeerCredentials(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "kone-helper-")
	require.NoError(t, err)
	defer os.RemoveAll(directory)
	base := filepath.Join(directory, "kone")
	commands, err := net.Listen("unix", base+"-commands.sock")
	require.NoError(t, err)
	defer commands.Close()
	events, err := net.Listen("unix", base+"-events.sock")
	require.NoError(t, err)
	defer events.Close()
	for _, suffix := range []string{"-commands.sock", "-events.sock"} {
		require.NoError(t, os.Chmod(base+suffix, 0600))
	}
	owner, err := darwinSocketOwner(base)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Geteuid()), owner)
	_, err = darwinSocketOwner(filepath.Join(directory, "wrong"))
	require.Error(t, err)
	require.NoError(t, os.Chmod(directory, 0755))
	_, err = darwinSocketOwner(base)
	require.Error(t, err)
	require.NoError(t, os.Chmod(directory, 0700))
	client, err := net.Dial("unix", base+"-commands.sock")
	require.NoError(t, err)
	defer client.Close()
	accepted, err := commands.Accept()
	require.NoError(t, err)
	defer accepted.Close()
	pid, uid, err := darwinPeer(accepted)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Getpid()), pid)
	require.Equal(t, uint32(os.Geteuid()), uid)
	require.Error(t, verifyDarwinPeer(context.Background(), uint32(os.Getpid())))
	path, started, err := darwinProcessIdentity(context.Background(), uint32(os.Getpid()))
	require.NoError(t, err)
	require.NotEmpty(t, started)
	executable, err := os.Executable()
	require.NoError(t, err)
	executable, err = filepath.EvalSymlinks(executable)
	require.NoError(t, err)
	require.Equal(t, executable, path)
}

func TestDarwinPublicHelperPreflightPreservesBlockingIssues(t *testing.T) {
	require.True(t, PrivilegeSeparationAvailable(), "native IPC and UTUN acceptance enable the public macOS helper")
	require.Equal(t, os.Geteuid() != 0, NeedsHelper())
	require.Equal(t, os.Geteuid() != 0, TrayAvailable(), "ordinary desktop entry attempts a bounded runtime READY handshake")
	cfg := kone.DefaultConfig()
	cfg.Core.Network = "198.18.239.1/24"
	report := Preflight(context.Background(), cfg)
	if NeedsHelper() {
		found := false
		for _, issue := range report.Issues {
			if issue.Code == "privileges" {
				found = true
				require.Equal(t, "info", issue.Severity)
				require.Contains(t, issue.Message, "explicit macOS administrator authorization")
			}
		}
		require.True(t, found, "ordinary management must explain deferred helper authorization")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, RunTray(ctx, TrayActions{}), "canceled tray startup must not launch a desktop process")
	report = Preflight(ctx, cfg)
	require.False(t, report.Ready, "the helper can relax only the privilege issue, never a real blocker")
	require.Contains(t, report.Issues, kone.PreflightIssue{Code: "canceled", Severity: "error", Message: context.Canceled.Error()})
	_, err := NewEngine(cfg, nil)
	require.ErrorContains(t, err, "authorization launcher")
}

func TestDarwinPrivateHelperSubprocess(t *testing.T) {
	if os.Getenv("KONE_PRIVATE_DARWIN_TEST") != "1" {
		return
	}
	args := flag.Args()
	require.Len(t, args, 4)
	pid, err := strconv.ParseUint(args[3], 10, 32)
	require.NoError(t, err)
	err = runDarwinNetworkHelper(context.Background(), args[1], uint32(pid), func(cfg *kone.KoneConfig) (NetworkEngine, error) { return newFakeNetworkEngine(t, cfg), nil })
	require.NoError(t, err)
}

func TestDarwinAuthenticatedPrivateHelperLifecycleWithoutNetworkChanges(t *testing.T) {
	if os.Geteuid() != 0 {
		if err := exec.Command("/usr/bin/sudo", "-n", "true").Run(); err != nil {
			if os.Getenv("CI") == "true" {
				t.Fatal("native macOS CI must provide noninteractive administrator access to verify helper ownership")
			}
			t.Skip("noninteractive administrator access is unavailable; never shows an authorization dialog")
		}
	}
	for _, disconnect := range []bool{false, true} {
		t.Run(strconv.FormatBool(disconnect), func(t *testing.T) {
			cfg := kone.DefaultConfig()
			cfg.DNS.Servers = []string{"127.0.0.1:5353"}
			var child *exec.Cmd
			var childOutput bytes.Buffer
			remote, err := darwinNewEngine(cfg, func(ctx context.Context, executable string, args []string) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				arguments := append([]string{"-test.run=^TestDarwinPrivateHelperSubprocess$", "--"}, args...)
				if os.Geteuid() == 0 {
					child = exec.Command(executable, arguments...)
					child.Env = append(os.Environ(), "KONE_PRIVATE_DARWIN_TEST=1")
				} else {
					arguments = append([]string{"-n", "/usr/bin/env", "KONE_PRIVATE_DARWIN_TEST=1", executable}, arguments...)
					child = exec.Command("/usr/bin/sudo", arguments...)
				}
				child.Stdout, child.Stderr = &childOutput, &childOutput
				t.Cleanup(func() {
					if child.Process != nil && child.ProcessState == nil {
						child.Process.Kill()
						child.Wait()
					}
				})
				return child.Start()
			})
			require.NoError(t, err)
			defer remote.Close()
			done := startRemote(t, remote)
			traffic, _, err := remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{})
			require.NoError(t, err)
			require.Equal(t, uint64(40), traffic.Totals.Bytes)
			if disconnect {
				remote.mu.Lock()
				commands, events := remote.commands, remote.events
				remote.mu.Unlock()
				commands.Close()
				events.Close()
				require.Error(t, <-done)
				require.Error(t, remote.Close())
			} else {
				require.NoError(t, remote.Close())
				require.NoError(t, <-done)
			}
			waited := make(chan error, 1)
			go func() { waited <- child.Wait() }()
			select {
			case err := <-waited:
				require.NoError(t, err, childOutput.String())
			case <-time.After(5 * time.Second):
				t.Fatal("administrator helper failed to exit after its private parent connection closed")
			}
		})
	}
}

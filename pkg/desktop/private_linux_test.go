package desktop

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestLinuxPrivateHelperSubprocess(t *testing.T) {
	if os.Getenv("KONE_PRIVATE_LINUX_TEST") != "1" {
		return
	}
	args := flag.Args()
	require.Len(t, args, 4)
	pid, err := strconv.ParseUint(args[3], 10, 32)
	require.NoError(t, err)
	err = runLinuxNetworkHelper(context.Background(), args[1], uint32(pid), func(cfg *kone.KoneConfig) (NetworkEngine, error) { return newFakeNetworkEngine(t, cfg), nil })
	require.NoError(t, err)
}

func TestLinuxAuthenticatedPrivateHelperLifecycleWithoutNetworkChanges(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("CI") != "true" {
			t.Skip("privileged IPC acceptance runs in CI; no host authorization is requested")
		}
		if err := exec.Command("/usr/bin/sudo", "-n", "true").Run(); err != nil {
			if os.Getenv("CI") == "true" {
				t.Fatal("native Linux CI must provide noninteractive administrator access to verify helper ownership")
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
			waited := make(chan error, 1)
			remote, err := linuxNewEngine(cfg, func(ctx context.Context, executable string, args []string) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				arguments := append([]string{"-test.run=^TestLinuxPrivateHelperSubprocess$", "--"}, args...)
				if os.Geteuid() == 0 {
					child = exec.Command(executable, arguments...)
					child.Env = append(os.Environ(), "KONE_PRIVATE_LINUX_TEST=1")
				} else {
					arguments = append([]string{"-n", "/usr/bin/env", "KONE_PRIVATE_LINUX_TEST=1", executable}, arguments...)
					child = exec.Command("/usr/bin/sudo", arguments...)
				}
				child.Stdout, child.Stderr = &childOutput, &childOutput
				t.Cleanup(func() {
					if child.Process != nil {
						_ = child.Process.Kill()
					}
				})
				if err := child.Start(); err != nil {
					return err
				}
				err := child.Wait()
				waited <- err
				return err
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
			select {
			case err := <-waited:
				require.NoError(t, err, childOutput.String())
				require.Eventually(t, func() bool { return len(authorizationSlot) == 0 }, time.Second, time.Millisecond)
			case <-time.After(5 * time.Second):
				t.Fatal("administrator helper failed to exit after its private parent connection closed")
			}
		})
	}
}

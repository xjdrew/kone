package desktop

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestWindowsPrivateTransportRejectsUnknownIdentity(t *testing.T) {
	require.True(t, validPipeBase(pipePrefix+strings.Repeat("a", 64)))
	for _, base := range []string{"", `\\remote\pipe\kone-` + strings.Repeat("a", 64), pipePrefix + strings.Repeat("g", 64), pipePrefix + strings.Repeat("a", 63)} {
		require.False(t, validPipeBase(base))
	}
	require.Error(t, verifyPeer(0, true))
	require.Error(t, verifyPeer(uint32(os.Getpid()), true))
	require.Error(t, RunNetworkHelper(context.Background(), "invalid", 0))
	_, err := NewEngine(kone.DefaultConfig(), nil)
	require.Error(t, err)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		require.Equal(t, uintptr(976), unsafe.Sizeof(trayIconData{}))
		require.Equal(t, uintptr(80), unsafe.Sizeof(trayWindowClass{}))
	}
}

func TestWindowsPrivatePipeHelperSubprocess(t *testing.T) {
	if os.Getenv("KONE_PRIVATE_PIPE_TEST") != "1" {
		return
	}
	args := flag.Args()
	require.Len(t, args, 4)
	pid, err := strconv.ParseUint(args[3], 10, 32)
	require.NoError(t, err)
	err = runNetworkHelper(context.Background(), args[1], uint32(pid), func(cfg *kone.KoneConfig) (NetworkEngine, error) { return newFakeNetworkEngine(t, cfg), nil })
	require.NoError(t, err)
}

// Uses the actual authenticated Windows named pipes and a separate process,
// but the helper's network implementation is entirely in memory.
func TestWindowsAuthenticatedHelperIPCWithoutNetworkChanges(t *testing.T) {
	if NeedsHelper() {
		t.Skip("requires the already elevated disposable Windows CI runner; never requests UAC")
	}
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	var child *exec.Cmd
	var childOutput bytes.Buffer
	remote, err := NewEngine(cfg, func(ctx context.Context, executable string, args []string) error {
		commandArgs := append([]string{"-test.run=^TestWindowsPrivatePipeHelperSubprocess$", "--"}, args...)
		if err := ctx.Err(); err != nil {
			return err
		}
		child = exec.Command(executable, commandArgs...)
		child.Env = append(os.Environ(), "KONE_PRIVATE_PIPE_TEST=1")
		child.Stdout = &childOutput
		child.Stderr = &childOutput
		child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
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
	require.NoError(t, remote.Close())
	require.NoError(t, <-done)
	waited := make(chan error, 1)
	go func() { waited <- child.Wait() }()
	select {
	case err := <-waited:
		require.NoError(t, err, childOutput.String())
	case <-time.After(3 * time.Second):
		t.Fatal("private helper did not exit")
	}
}

package integration

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
)

func TestLinuxNativeNetworkHelperWorker(t *testing.T) {
	if os.Getenv("KONE_LINUX_NATIVE_HELPER") != "1" {
		return
	}
	args := flag.Args()
	require.Len(t, args, 4)
	pid, err := strconv.ParseUint(args[3], 10, 32)
	require.NoError(t, err)
	require.NoError(t, desktop.RunNetworkHelper(t.Context(), args[1], uint32(pid)))
}

func TestSystemLifecycleLinuxHelper(t *testing.T) {
	// systemConfig restricts real TUN mutation to the existing disposable CI
	// namespace. Authorization itself is not shown on headless CI.
	cfg := systemConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	childDone := make(chan error, 1)
	var output bytes.Buffer
	remote, err := desktop.NewEngine(cfg, func(ctx context.Context, executable string, args []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		arguments := append([]string{"-test.run=^TestLinuxNativeNetworkHelperWorker$", "--"}, args...)
		child := exec.Command(executable, arguments...)
		child.Env = append(os.Environ(), "KONE_LINUX_NATIVE_HELPER=1")
		child.Stdout, child.Stderr = &output, &output
		if err := child.Start(); err != nil {
			childDone <- err
			return err
		}
		t.Cleanup(func() { _ = child.Process.Kill() })
		err := child.Wait()
		childDone <- err
		return err
	})
	require.NoError(t, err)
	defer remote.Close()
	require.NoError(t, remote.SetCaptureRecorder(func(name string, index int) error {
		device, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		if name != cfg.Core.Tun || device.Index != index {
			return fmt.Errorf("unexpected capture identity %s/%d", name, index)
		}
		return nil
	}))
	done := make(chan error, 1)
	go func() { done <- remote.Run(ctx) }()
	select {
	case <-remote.Ready():
	case err := <-done:
		t.Fatalf("helper startup: %v", err)
	case <-ctx.Done():
		t.Fatal("helper did not become ready")
	}
	_, err = net.InterfaceByName(cfg.Core.Tun)
	require.NoError(t, err)
	endpoint, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer endpoint.Close()
	go func() {
		conn, err := endpoint.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	result, err := remote.ProbeDiagnostic(ctx, "direct", endpoint.Addr().String(), false)
	require.NoError(t, err)
	require.Equal(t, "reachable", result.Status)
	require.NoError(t, remote.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("remote engine failed to stop")
	}
	select {
	case err := <-childDone:
		require.NoError(t, err, output.String())
	case <-ctx.Done():
		t.Fatal("network helper failed to exit")
	}
	noSystemInterface(t, cfg)
}

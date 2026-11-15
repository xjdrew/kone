package desktop

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestLinuxDeferredAuthorizationDoesNotHideBlockers(t *testing.T) {
	for _, available := range []bool{true, false} {
		report := linuxAuthorizationPreflight(kone.PreflightReport{Issues: []kone.PreflightIssue{{Code: "privileges", Severity: "error"}}}, available)
		require.Equal(t, available, report.Ready)
		if available {
			require.Equal(t, "info", report.Issues[0].Severity)
		} else {
			require.Equal(t, "authorization_unavailable", report.Issues[0].Code)
		}
		report.Issues = append(report.Issues, kone.PreflightIssue{Code: "network_overlap", Severity: "error"})
		require.False(t, linuxAuthorizationPreflight(report, available).Ready)
	}
	require.True(t, PrivilegeSeparationAvailable())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.False(t, Preflight(ctx, kone.DefaultConfig()).Ready)
	_, err := NewEngine(kone.DefaultConfig(), nil)
	require.Error(t, err)
	require.Error(t, RunNetworkHelper(ctx, "/invalid", 0))
}

func TestLinuxPrivateSocketOwnershipAndCredentials(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "kone-helper-")
	require.NoError(t, err)
	defer os.RemoveAll(directory)
	base := filepath.Join(directory, "kone")
	var listeners []net.Listener
	for _, suffix := range []string{"-commands.sock", "-events.sock"} {
		listener, err := net.Listen("unix", base+suffix)
		require.NoError(t, err)
		defer listener.Close()
		listeners = append(listeners, listener)
		require.NoError(t, os.Chmod(base+suffix, 0600))
	}
	owner, err := linuxSocketOwner(base)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Geteuid()), owner)
	require.NoError(t, os.Chmod(directory, 0755))
	_, err = linuxSocketOwner(base)
	require.Error(t, err)
	require.NoError(t, os.Chmod(directory, 0700))
	require.NoError(t, os.Chmod(base+"-commands.sock", 0666))
	_, err = linuxSocketOwner(base)
	require.Error(t, err)
	require.NoError(t, os.Chmod(base+"-commands.sock", 0600))
	_, err = linuxSocketOwner(filepath.Join(directory, "invalid"))
	require.Error(t, err)
	client, err := net.Dial("unix", base+"-commands.sock")
	require.NoError(t, err)
	defer client.Close()
	conn, err := listeners[0].Accept()
	require.NoError(t, err)
	defer conn.Close()
	pid, uid, err := linuxPeer(conn)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Getpid()), pid)
	require.Equal(t, owner, uid)
	require.Error(t, verifyLinuxParent(pid))
	require.Error(t, verifyLinuxParent(0))
	require.Error(t, verifyLinuxParent(^uint32(0)))
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_, _, err = linuxPeer(left)
	require.Error(t, err)
}

func TestLinuxAuthorizationRejectionReturnsWithoutWaitingForSocketTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	rejected := &AuthorizationError{Code: "authorization_canceled", Cause: errors.New("dismissed")}
	_, _, err := connectLinux(ctx, func(context.Context, string, []string) error { return rejected })
	require.ErrorIs(t, err, rejected)
	require.NoError(t, ctx.Err())
}

func TestLinuxCanceledAuthorizationCannotConnectLate(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan string, 1)
	release := make(chan struct{})
	defer func() {
		close(release)
		require.Eventually(t, func() bool { return len(authorizationSlot) == 0 }, time.Second, time.Millisecond)
	}()
	done := make(chan error, 1)
	go func() {
		_, _, err := connectLinux(ctx, func(_ context.Context, _ string, args []string) error {
			entered <- args[1]
			<-release
			return nil
		})
		done <- err
	}()
	var base string
	select {
	case base = <-entered:
	case <-time.After(time.Second):
		t.Fatal("authorization did not start")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for the system dialog")
	}
	_, err := os.Stat(filepath.Dir(base))
	require.True(t, os.IsNotExist(err))
	conn, err := net.Dial("unix", base+"-commands.sock")
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err, "late authorization must not resurrect a canceled session")
}

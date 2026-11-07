package integration

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
)

const routeConsoleTraceEnvironment = "KONE_TEST_ROUTE_CONSOLE_TRACE"

func init() {
	trace := os.Getenv(routeConsoleTraceEnvironment)
	if trace == "" || !strings.EqualFold(filepath.Base(os.Args[0]), "route.exe") {
		return
	}
	// A PATH sentinel: periodic inspection must use GetIpForwardTable2,
	// never a subprocess that can create a console window.
	if err := os.WriteFile(trace, []byte("route.exe invoked"), 0600); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestWindowsPeriodicNetworkInspectionDoesNotCreateConsole(t *testing.T) {
	directory := t.TempDir()
	executable, err := os.Executable()
	require.NoError(t, err)
	source, err := os.Open(executable)
	require.NoError(t, err)
	defer source.Close()
	helper, err := os.Create(filepath.Join(directory, "route.exe"))
	require.NoError(t, err)
	_, copyErr := io.Copy(helper, source)
	closeErr := helper.Close()
	require.NoError(t, copyErr)
	require.NoError(t, closeErr)
	trace := filepath.Join(directory, "console-states.txt")
	t.Setenv(routeConsoleTraceEnvironment, trace)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(t.Context(), 2200*time.Millisecond)
	defer cancel()
	changes := control.WatchNetworkChanges(ctx, "", time.Second)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case change, open := <-changes:
			if !open {
				_, err := os.Stat(trace)
				require.ErrorIs(t, err, os.ErrNotExist, "native inspection must not execute route.exe")
				return
			}
			// A real host change may end the watcher early; failed native reads
			// are still failures, not permission to substitute shell commands.
			require.Equal(t, "environment_changed", change.Kind)
			require.Empty(t, change.Error)
		case <-deadline:
			t.Fatal("periodic network inspection did not stop after cancellation")
		}
	}
}

package integration

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"golang.org/x/sys/windows"
)

const routeConsoleTraceEnvironment = "KONE_TEST_ROUTE_CONSOLE_TRACE"

func init() {
	trace := os.Getenv(routeConsoleTraceEnvironment)
	if trace == "" || !strings.EqualFold(filepath.Base(os.Args[0]), "route.exe") {
		return
	}
	// This copied test binary stands in for route.exe. It never queries or
	// changes the host route table, and reports its own actual console state.
	if len(os.Args) != 3 || os.Args[1] != "print" || os.Args[2] != "-4" {
		os.Exit(2)
	}
	window, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	previous, _ := os.ReadFile(trace)
	file, err := os.OpenFile(trace, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		os.Exit(3)
	}
	_, err = fmt.Fprintf(file, "%t\n", window != 0)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		os.Exit(4)
	}
	// The second read changes only this simulated result, so the real watcher
	// emits a route change and exits after exercising its periodic command.
	fmt.Fprintf(os.Stdout, "simulated-route-generation-%d\n", len(previous))
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
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	changes := control.WatchNetworkChanges(ctx, "", time.Second)
	select {
	case change, open := <-changes:
		require.True(t, open, "the periodic route inspection must run")
		require.Equal(t, "environment_changed", change.Kind)
		require.Contains(t, change.Changed, "routes")
		require.Empty(t, change.Error)
	case <-ctx.Done():
		t.Fatal("periodic network inspection did not finish")
	}
	states, err := os.ReadFile(trace)
	require.NoError(t, err)
	require.Equal(t, "false\nfalse\n", string(states), "initial and periodic inspection must both have no console")
}

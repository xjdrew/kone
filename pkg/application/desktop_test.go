package application

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
)

func TestConsoleVersionUsesEntrypointBuildIdentity(t *testing.T) {
	var output, diagnostics bytes.Buffer
	require.Zero(t, Run(context.Background(), []string{"-version"}, &output, &diagnostics, "0.4.0-test"))
	require.Equal(t, "Version: 0.4.0-test\n", output.String())
	require.Empty(t, diagnostics.String())
}

func TestManagementPresentationKeepsDesktopTrayIndependentOfBrowser(t *testing.T) {
	for _, tc := range []struct {
		gui, noBrowser, noTray bool
		browser, tray          bool
	}{
		{false, false, false, true, true},
		{false, true, false, false, false},
		{true, false, false, false, true},
		{true, true, false, false, true},
		{true, false, true, false, false},
	} {
		browser, tray := managementPresentation(tc.gui, tc.noBrowser, tc.noTray)
		require.Equal(t, tc.browser, browser)
		require.Equal(t, tc.tray, tray)
	}
}

func TestDesktopStartupFailureIsReportedWithoutRawArguments(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	var notified []int
	code := runDesktop(context.Background(), []string{"-unknown-secret-do-not-display"}, "test", func(code int) { notified = append(notified, code) })
	require.Equal(t, 2, code)
	require.Equal(t, []int{2}, notified)
	require.NotContains(t, desktopFailureMessage(code), "unknown-secret")
	require.Contains(t, desktopFailureMessage(code), "kone-cli")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Zero(t, runDesktop(ctx, nil, "test", func(int) { t.Fatal("canceled startup is not a failure") }))
	require.Equal(t, 2, runDesktop(context.Background(), []string{"-network-helper", "invalid"}, "test", func(int) { t.Fatal("an internal helper must report through its parent instead of opening a dialog") }))
}

func TestNetworkHelperDetectionDoesNotReadPastEndOfOptions(t *testing.T) {
	require.True(t, networkHelperInvocation([]string{"--network-helper=owned-pipe"}))
	require.False(t, networkHelperInvocation([]string{"--", "-network-helper"}))
	require.False(t, networkHelperInvocation([]string{"-config", "config.toml"}))
	require.False(t, networkHelperInvocation([]string{"-data-dir", "-network-helper"}))
	require.False(t, networkHelperInvocation([]string{"-unknown", "-network-helper"}))
}

func TestDesktopManagementWaitsForTrayActionAndNeverPrintsBootstrapURL(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan string, 1)
	result := make(chan int, 1)
	var output bytes.Buffer
	options := runOptions{
		version: "desktop-test", desktop: true,
		browser:       func(url string) error { opened <- url; return nil },
		trayAvailable: func() bool { return true },
		tray: func(ctx context.Context, actions desktop.TrayActions) error {
			select {
			case <-opened:
				t.Error("desktop opened a browser before the tray action")
			default:
			}
			actions.Open()
			<-ctx.Done()
			return nil
		},
	}
	go func() {
		result <- runWithOptions(ctx, []string{"-data-dir", t.TempDir(), "-listen", "127.0.0.1:0"}, &output, io.Discard,
			func(context.Context, string, bool, io.Writer) (bool, error) {
				t.Error("paused management requested elevation")
				return false, nil
			}, options)
	}()
	select {
	case url := <-opened:
		require.Contains(t, url, "127.0.0.1:")
	case <-time.After(3 * time.Second):
		t.Fatal("tray browser action did not become available")
	}
	cancel()
	select {
	case code := <-result:
		require.Zero(t, code)
	case <-time.After(3 * time.Second):
		t.Fatal("desktop management did not stop")
	}
	require.Empty(t, output.String())
}

func TestDesktopTrayFailureStopsTheInvisibleManagementProcess(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	options := runOptions{version: "test", desktop: true, trayAvailable: func() bool { return true },
		tray: func(context.Context, desktop.TrayActions) error { return errors.New("injected tray startup failure") }}
	var diagnostics bytes.Buffer
	code := runWithOptions(ctx, []string{"-data-dir", t.TempDir(), "-listen", "127.0.0.1:0"}, io.Discard, &diagnostics, elevateForWindows, options)
	require.Equal(t, 3, code)
	require.Contains(t, diagnostics.String(), "injected tray startup failure")
}

func TestDesktopWithoutAnAvailableTrayDoesNotRemainInvisible(t *testing.T) {
	var diagnostics bytes.Buffer
	code := runWithOptions(context.Background(), nil, io.Discard, &diagnostics, elevateForWindows,
		runOptions{version: "test", desktop: true, trayAvailable: func() bool { return false }})
	require.Equal(t, 3, code)
	require.Contains(t, diagnostics.String(), "tray is unavailable")
}

package application

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
)

func TestCaptureTrayFailureReportsSafeFeedbackAndDiagnostics(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, gui := range []bool{false, true} {
		for _, action := range []string{"start", "pause"} {
			var output bytes.Buffer
			slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
			var opened, notices []string
			callback := captureTrayAction(context.Background(), action, func(ctx context.Context) error {
				deadline, bounded := ctx.Deadline()
				require.True(t, bounded)
				require.WithinDuration(t, time.Now().Add(20*time.Second), deadline, time.Second)
				return errors.New("injected capture failure")
			}, func() (string, error) { return "http://127.0.0.1:9200/#token=private-bootstrap", nil }, runOptions{
				desktop:       gui,
				browser:       func(url string) error { opened = append(opened, url); return nil },
				captureNotice: func(value string) { notices = append(notices, captureFailureMessage(value)) },
			})
			callback()
			require.Equal(t, []string{"http://127.0.0.1:9200/#token=private-bootstrap&page=diagnostics"}, opened)
			if gui {
				require.Len(t, notices, 1)
			} else {
				require.Empty(t, notices)
			}
			require.Contains(t, output.String(), "level=ERROR")
			require.Contains(t, output.String(), "injected capture failure")
			require.NotContains(t, output.String(), "private-bootstrap")
			require.NotContains(t, strings.Join(notices, ""), "private-bootstrap")
		}
	}
}

func TestSuccessfulCaptureTrayActionsHaveNoInterruptingFeedback(t *testing.T) {
	for _, action := range []string{"start", "pause"} {
		captureTrayAction(context.Background(), action, func(context.Context) error { return nil },
			func() (string, error) { t.Fatal("success must not mint a bootstrap URL"); return "", nil }, runOptions{
				desktop:       true,
				browser:       func(string) error { t.Fatal("success must not open a browser"); return nil },
				captureNotice: func(string) { t.Fatal("success must not open a dialog") },
			})()
	}
}

func TestCaptureDiagnosticsFailuresStillLeaveVisibleFeedback(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, failure := range []string{"access", "url", "browser"} {
		var output bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
		notices := 0
		captureTrayAction(context.Background(), "start", func(context.Context) error { return errors.New("capture failed") },
			func() (string, error) {
				if failure == "access" {
					return "", errors.New("access unavailable")
				}
				if failure == "url" {
					return "https://example.invalid/#token=untrusted", nil
				}
				return "http://127.0.0.1:9200/#token=owned", nil
			}, runOptions{desktop: true, browser: func(string) error { return errors.New("browser unavailable") }, captureNotice: func(string) { notices++ }})()
		require.Equal(t, 1, notices)
		require.Contains(t, output.String(), "Could not open capture diagnostics")
	}
}

func TestFailedTrayStartKeepsDesktopManagementAvailable(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	feedback := make(chan string, 2)
	state := make(chan string, 1)
	result := make(chan int, 1)
	options := runOptions{version: "test", desktop: true, trayAvailable: func() bool { return true },
		browser:       func(url string) error { feedback <- url; return nil },
		captureNotice: func(action string) { feedback <- action },
		tray: func(ctx context.Context, actions desktop.TrayActions) error {
			actions.Start() // The default profile has no enabled TUN inbound.
			state <- actions.State()
			<-ctx.Done()
			return nil
		}}
	go func() {
		result <- runWithOptions(ctx, []string{"-data-dir", t.TempDir(), "-listen", "127.0.0.1:0"}, io.Discard, io.Discard, elevateForWindows, options)
	}()
	select {
	case value := <-state:
		require.Equal(t, "paused", value)
	case <-time.After(3 * time.Second):
		t.Fatal("failed capture did not return control to management")
	}
	require.Contains(t, <-feedback, "page=diagnostics")
	require.Equal(t, "start", <-feedback)
	select {
	case code := <-result:
		t.Fatalf("capture failure stopped management with code %d", code)
	default:
	}
	cancel()
	select {
	case code := <-result:
		require.Zero(t, code)
	case <-time.After(3 * time.Second):
		t.Fatal("management did not stop after cancellation")
	}
}

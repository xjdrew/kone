package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/logstore"
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
		{false, false, true, true, false},
		{false, true, true, false, false},
		{true, false, false, true, true},
		{true, true, false, false, true},
		{true, false, true, true, false},
		{true, true, true, false, false},
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
	code := runDesktop(context.Background(), []string{"-unknown-secret-do-not-display"}, "test", func(code int, message string) {
		notified = append(notified, code)
		require.NotContains(t, message, "unknown-secret")
	})
	require.Equal(t, 2, code)
	require.Equal(t, []int{2}, notified)
	require.NotContains(t, desktopFailureMessage(code, errors.New("private startup detail")), "private startup detail")
	require.Contains(t, desktopFailureMessage(code, nil), "kone-cli")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Zero(t, runDesktop(ctx, nil, "test", func(int, string) { t.Fatal("canceled startup is not a failure") }))
	require.Equal(t, 2, runDesktop(context.Background(), []string{"-network-helper", "invalid"}, "test", func(int, string) {
		t.Fatal("an internal helper must report through its parent instead of opening a dialog")
	}))
}

func TestNetworkHelperDetectionDoesNotReadPastEndOfOptions(t *testing.T) {
	require.True(t, networkHelperInvocation([]string{"--network-helper=owned-pipe"}))
	require.False(t, networkHelperInvocation([]string{"--", "-network-helper"}))
	require.False(t, networkHelperInvocation([]string{"-config", "config.toml"}))
	require.False(t, networkHelperInvocation([]string{"-data-dir", "-network-helper"}))
	require.False(t, networkHelperInvocation([]string{"-unknown", "-network-helper"}))
}

func TestDesktopManagementOpensManuallyOrWaitsQuietlyAndTrayCanReopen(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, quiet := range []bool{false, true} {
		for _, configured := range []bool{false, true} {
			t.Run(fmt.Sprintf("quiet=%t/configured=%t", quiet, configured), func(t *testing.T) {
				directory := t.TempDir()
				if configured {
					// A valid-shaped synthetic credential file is sufficient to test
					// startup presentation; no password login is performed here.
					auth, err := json.Marshal(map[string]any{"version": 2, "salt": make([]byte, 16), "hash": make([]byte, 32)})
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(filepath.Join(directory, "auth.json"), auth, 0600))
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				opened := make(chan string, 2)
				tray := make(chan desktop.TrayActions, 1)
				result := make(chan int, 1)
				var output bytes.Buffer
				options := runOptions{version: "desktop-test", desktop: true,
					browser:       func(url string) error { opened <- url; return nil },
					browserNotice: func() { t.Error("successful browser launch showed a failure notice") },
					trayAvailable: func() bool { return true },
					tray: func(ctx context.Context, actions desktop.TrayActions) error {
						tray <- actions
						<-ctx.Done()
						return nil
					},
				}
				args := []string{"-data-dir", directory, "-listen", "127.0.0.1:0"}
				if quiet {
					args = append(args, "-no-browser")
				}
				go func() {
					result <- runWithOptions(ctx, args, &output, io.Discard, func(context.Context, string, bool, io.Writer) (bool, error) {
						t.Error("paused management requested elevation")
						return false, nil
					}, options)
				}()
				var actions desktop.TrayActions
				select {
				case actions = <-tray:
				case <-time.After(3 * time.Second):
					t.Fatal("tray did not start")
				}
				require.Equal(t, "paused", actions.State())
				checkURL := func() {
					select {
					case raw := <-opened:
						parsed, err := url.Parse(raw)
						require.NoError(t, err)
						require.Equal(t, "127.0.0.1", parsed.Hostname())
						if configured {
							require.Empty(t, parsed.Fragment)
						} else {
							require.Contains(t, parsed.Fragment, "token=")
						}
					case <-time.After(3 * time.Second):
						t.Fatal("browser was not opened")
					}
				}
				if quiet {
					select {
					case <-opened:
						t.Fatal("quiet desktop launch opened a browser")
					default:
					}
				} else {
					checkURL()
				}
				actions.Open()
				checkURL()
				cancel()
				select {
				case code := <-result:
					require.Zero(t, code)
				case <-time.After(3 * time.Second):
					t.Fatal("desktop management did not stop")
				}
				require.Empty(t, output.String())
				_, err := os.Stat(filepath.Join(directory, "capture.json"))
				require.True(t, os.IsNotExist(err), "opening management never starts capture")
			})
		}
	}
}

func TestDesktopBrowserFailureFeedbackDoesNotBlockHTTPOrExposeSetupSecrets(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan string, 1)
	notice := make(chan struct{}, 1)
	noticeDone := make(chan struct{})
	launchRelease, noticeRelease := make(chan struct{}), make(chan struct{})
	var releaseLaunch, releaseNotice sync.Once
	allowLaunch := func() { releaseLaunch.Do(func() { close(launchRelease) }) }
	allowNotice := func() { releaseNotice.Do(func() { close(noticeRelease) }) }
	t.Cleanup(allowLaunch)
	t.Cleanup(allowNotice)
	store := logstore.New()
	result := make(chan int, 1)
	var output bytes.Buffer
	options := runOptions{version: "desktop-test", desktop: true, logs: store,
		browser: func(raw string) error {
			opened <- raw
			<-launchRelease
			return fmt.Errorf("private-browser-detail %s", raw)
		},
		browserNotice: func() { notice <- struct{}{}; <-noticeRelease; close(noticeDone) },
		trayAvailable: func() bool { return true },
		tray:          func(ctx context.Context, _ desktop.TrayActions) error { <-ctx.Done(); return nil },
	}
	go func() {
		result <- runWithOptions(ctx, []string{"-data-dir", t.TempDir(), "-listen", "127.0.0.1:0"}, &output, io.Discard, elevateForWindows, options)
	}()
	var raw string
	select {
	case raw = <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("startup browser did not run")
	}
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	token := parsed.Fragment
	parsed.Fragment = ""
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	assertHTTPReady := func() {
		response, err := client.Get(parsed.String() + "api/v1/auth")
		require.NoError(t, err, "browser activation and native dialogs cannot block HTTP serving")
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Contains(t, string(data), `"setup_required":true`)
	}
	assertHTTPReady()
	allowLaunch()
	select {
	case <-notice:
	case <-time.After(3 * time.Second):
		t.Fatal("browser failure did not show safe feedback")
	}
	assertHTTPReady()
	require.Contains(t, browserFailureMessage(), "管理服务已在后台运行")
	require.NotContains(t, browserFailureMessage(), "接管已启用")
	cancel()
	select {
	case code := <-result:
		require.Zero(t, code)
	case <-time.After(3 * time.Second):
		t.Fatal("notice blocked management shutdown")
	}
	allowNotice()
	select {
	case <-noticeDone:
	case <-time.After(time.Second):
		t.Fatal("notice callback did not finish")
	}
	page, err := store.Query(logstore.Query{Tail: true, Limit: 200})
	require.NoError(t, err)
	encoded, err := json.Marshal(page)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), token)
	require.NotContains(t, string(encoded), "private-browser-detail")
	require.Empty(t, output.String())
}

func TestDesktopTrayFailureStopsTheInvisibleManagementProcess(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	options := runOptions{version: "test", desktop: true, trayAvailable: func() bool { return true },
		browser: func(string) error { return nil },
		tray:    func(context.Context, desktop.TrayActions) error { return errors.New("injected tray startup failure") }}
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

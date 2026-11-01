package application

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/logstore"
)

func TestOrdinaryManagementStartupEmitsInfoLogsWithoutCapture(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	store := logstore.New()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := managementOutput{make(chan string, 1)}
	done := make(chan int, 1)
	go func() {
		done <- runWithOptions(ctx, []string{"-data-dir", t.TempDir(), "-listen", "127.0.0.1:0", "-no-browser", "-no-tray"}, output, io.Discard, elevateForWindows, runOptions{version: "log-pipeline-test", logs: store})
	}()
	select {
	case <-output.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("ordinary management did not start")
	}
	page, err := store.Query(logstore.Query{MinLevel: "info"})
	require.NoError(t, err)
	messages := map[string]bool{}
	for _, record := range page.Records {
		messages[record.Message] = true
		require.Equal(t, "management", record.Source)
	}
	require.True(t, messages["Starting KONE management"])
	require.True(t, messages["Managed settings loaded; capture is paused"], "controller events and application events must reach the same instance store")
	require.True(t, messages["Local management is ready"])
	data, err := json.Marshal(page)
	require.NoError(t, err)
	require.NotContains(t, string(data), "#token=")
	require.NotContains(t, string(data), "csrf_token")
	require.NotContains(t, string(data), "http://127.0.0.1:")
	cancel()
	select {
	case code := <-done:
		require.Zero(t, code)
	case <-time.After(3 * time.Second):
		t.Fatal("management did not stop")
	}
	retained, err := store.Query(logstore.Query{})
	require.NoError(t, err)
	data, err = json.Marshal(retained)
	require.NoError(t, err)
	require.Contains(t, string(data), "Management service stopped")
	require.Contains(t, string(data), "Starting KONE management")
	require.False(t, strings.Contains(string(data), "network-helper="))
}

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/application"
	"github.com/xjdrew/kone/pkg/control"
)

func TestUnsupportedPasswordStartupPreservesAuthenticationAndSettings(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	directory := t.TempDir()
	manager, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	require.NoError(t, manager.Close())
	settingsPath := filepath.Join(directory, "settings.json")
	settings, err := os.ReadFile(settingsPath)
	require.NoError(t, err)
	authPath := filepath.Join(directory, "auth.json")
	auth, err := json.Marshal(map[string]any{"version": 1, "salt": []byte("0123456789abcdef"), "hash": make([]byte, 32)})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(authPath, auth, 0600))
	var output, diagnostics bytes.Buffer
	code := application.Run(context.Background(), []string{"-data-dir", directory, "-no-browser", "-no-tray"}, &output, &diagnostics, "startup-test")
	require.Equal(t, 3, code)
	require.Empty(t, output.String(), "failed startup cannot issue a setup URL")
	require.Contains(t, diagnostics.String(), "management password format is unsupported")
	require.Contains(t, diagnostics.String(), "auth.json")
	require.NotContains(t, diagnostics.String(), string(auth))
	for path, before := range map[string][]byte{authPath: auth, settingsPath: settings} {
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, before, after)
	}
	_, err = os.Stat(filepath.Join(directory, "capture.json"))
	require.True(t, os.IsNotExist(err), "failed management startup never starts capture")
}

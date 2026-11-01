package application

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
)

func TestDesktopUnsupportedPasswordFormatShowsLocalResetInstructions(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	directory := t.TempDir()
	path := filepath.Join(directory, "auth.json")
	data, err := json.Marshal(map[string]any{"version": 1, "salt": []byte("0123456789abcdef"), "hash": make([]byte, 32)})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	var notice string
	notifications := 0
	code := runDesktop(context.Background(), []string{"-data-dir", directory, "-no-tray"}, "test", func(code int, message string) {
		require.Equal(t, 3, code)
		notice = message
		notifications++
	})
	require.Equal(t, 3, code)
	require.Equal(t, 1, notifications)
	require.Contains(t, notice, "auth.json")
	require.Contains(t, notice, "备份并移出")
	require.Contains(t, notice, "settings.json")
	require.NotContains(t, notice, directory, "native notices do not expose raw command-line paths")
	require.Equal(t, desktopFailureMessage(3, fmt.Errorf("wrapped: %w", control.ErrPasswordFormatUnsupported)), notice)
	preserved, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, preserved, "a startup failure never deletes or rewrites authentication")
}

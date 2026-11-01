package application

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunElevationAfterValidation(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy", "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	config := filepath.Join(t.TempDir(), "config with spaces.toml")
	require.NoError(t, os.WriteFile(config, []byte("[dns]\nservers=['1.1.1.1']\n"), 0600))
	invalid := filepath.Join(t.TempDir(), "invalid.toml")
	require.NoError(t, os.WriteFile(invalid, []byte("[core]\nunknown=true\n"), 0600))
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"check", []string{"-check", "-config", config}, 0},
		{"version", []string{"-version"}, 0},
		{"help", []string{"-help"}, 0},
		{"invalid", []string{"-config", invalid}, 2},
		{"missing", []string{"-config", invalid + ".missing"}, 2},
		{"bad flag", []string{"-unknown"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			require.Equal(t, tc.code, runContextWithElevation(context.Background(), tc.args, &out, &stderr,
				func(context.Context, string, bool, io.Writer) (bool, error) {
					t.Fatal("read-only commands and invalid configuration must never request UAC")
					return false, nil
				}))
		})
	}
	t.Run("handoff", func(t *testing.T) {
		var out, stderr bytes.Buffer
		calls := 0
		code := runContextWithElevation(context.Background(), []string{"-debug", config}, &out, &stderr,
			func(_ context.Context, path string, debug bool, output io.Writer) (bool, error) {
				calls++
				require.Equal(t, config, path)
				require.True(t, debug)
				require.Same(t, &stderr, output)
				return true, nil
			})
		require.Equal(t, 0, code)
		require.Equal(t, 1, calls)
		require.NotContains(t, stderr.String(), "Starting KONE")
	})
	t.Run("authorization failure", func(t *testing.T) {
		var out, stderr bytes.Buffer
		code := runContextWithElevation(context.Background(), []string{"-config", config}, &out, &stderr,
			func(context.Context, string, bool, io.Writer) (bool, error) {
				return false, errors.New("injected authorization failure")
			})
		require.Equal(t, 3, code)
		require.Contains(t, stderr.String(), "injected authorization failure")
		require.NotContains(t, stderr.String(), "Starting KONE")
	})
	for _, disabled := range []bool{false, true} {
		name := "already elevated or non-Windows"
		args := []string{"-config", config}
		if disabled {
			name = "explicitly disabled"
			args = append([]string{"-no-elevate"}, args...)
		}
		t.Run(name, func(t *testing.T) {
			// Cancellation guarantees this continuation never changes networking,
			// including on administrator CI runners.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			calls := 0
			var out, stderr bytes.Buffer
			code := runContextWithElevation(ctx, args, &out, &stderr,
				func(context.Context, string, bool, io.Writer) (bool, error) {
					calls++
					return false, nil
				})
			require.Zero(t, code)
			if disabled {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
			require.Contains(t, stderr.String(), "Starting KONE")
		})
	}
}

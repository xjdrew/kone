package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNoArgumentManagementCanCancelWithoutConfigOrElevation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output, errors bytes.Buffer
	code := runContextWithElevation(ctx, nil, &output, &errors, func(context.Context, string, bool, io.Writer) (bool, error) {
		t.Fatal("management must not elevate before capture")
		return false, nil
	})
	require.Equal(t, 0, code)
}

type managementOutput struct{ ready chan string }

func (w managementOutput) Write(p []byte) (int, error) {
	select {
	case w.ready <- string(p):
	default:
	}
	return len(p), nil
}

func TestManagementIgnoresWorkingDirectoryConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile("config.toml", []byte("this is deliberately invalid"), 0600))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := managementOutput{make(chan string, 1)}
	result := make(chan int, 1)
	go func() {
		result <- runContext(ctx, []string{"-data-dir", t.TempDir(), "-listen", "127.0.0.1:0", "-no-browser"}, output, io.Discard)
	}()
	select {
	case line := <-output.ready:
		require.True(t, strings.Contains(line, "capture paused"))
	case <-time.After(3 * time.Second):
		t.Fatal("management did not become ready")
	}
	cancel()
	select {
	case code := <-result:
		require.Equal(t, 0, code)
	case <-time.After(3 * time.Second):
		t.Fatal("management did not stop")
	}
}

func TestManagementArgumentsNeverStartCapture(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		code    int
		message string
	}{
		{[]string{"-manage", "-config", "anything.toml"}, 2, "management loads"},
		{[]string{"-manage", "-data-dir", t.TempDir(), "-listen", "0.0.0.0:0", "-no-browser"}, 3, "loopback"},
	} {
		var output, errors bytes.Buffer
		code := runContextWithElevation(context.Background(), tc.args, &output, &errors, func(context.Context, string, bool, io.Writer) (bool, error) {
			t.Fatal("management must not elevate")
			return false, nil
		})
		require.Equal(t, tc.code, code)
		require.Contains(t, errors.String(), tc.message)
	}
}

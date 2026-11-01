package desktop

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/web"
)

func TestDarwinNativeTraySelectors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("native menu bar self-test requires an ordinary desktop user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/osascript", "-l", "JavaScript", "-e", web.MacOSTrayScript, "--", "--self-test")
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 77 && strings.Contains(diagnostics.String(), "KONE_TRAY_UNAVAILABLE") {
		t.Skip("WindowServer/AppKit notification area is unavailable in this macOS CI session")
	}
	require.NoError(t, err, diagnostics.String())
	require.Equal(t, "SELFTEST_OK", strings.TrimSpace(string(output)))
	t.Log("KONE_MAC_TRAY_NATIVE_VALIDATED: real AppKit menu selectors and state self-test passed")
}

func TestDarwinNativeTrayPipeEOF(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("native menu bar smoke requires an ordinary desktop user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/osascript", "-l", "JavaScript", "-e", web.MacOSTrayScript)
	input, err := command.StdinPipe()
	require.NoError(t, err)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	require.NoError(t, command.Start())
	defer func() {
		input.Close()
		if command.ProcessState == nil {
			command.Process.Kill()
			command.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	ready, readErr := reader.ReadString('\n')
	if readErr != nil {
		err = command.Wait()
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 77 && strings.Contains(diagnostics.String(), "KONE_TRAY_UNAVAILABLE") {
			t.Skip("WindowServer/AppKit notification area is unavailable in this macOS CI session")
		}
		t.Fatalf("native tray did not announce readiness: %v / %v / %s", readErr, err, diagnostics.String())
	}
	require.Equal(t, "READY", strings.TrimSpace(ready))
	_, err = io.WriteString(input, "{\"status\":\"paused\",\"detail\":\"KONE — 已暂停\",\"can_start\":true,\"can_pause\":false,\"can_diagnose\":true}\n")
	require.NoError(t, err)
	start := time.Now()
	require.NoError(t, input.Close())
	rest, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, command.Wait(), diagnostics.String())
	require.Empty(t, strings.TrimSpace(string(rest)), "ordinary native status updates cannot create unsolicited controller actions")
	require.Less(t, time.Since(start), 3*time.Second, "stdin EOF must remove the owned menu and stop the native helper")
	t.Log("KONE_MAC_TRAY_EOF_VALIDATED: real UTF-8 status pipe and owned AppKit cleanup passed")
}

package kone

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWindowsNetworkAndDNSCommandsDoNotCreateConsole(t *testing.T) {
	// Inspect only this harmless PowerShell process, never an adapter or route.
	// A hidden window alone still has a console; CREATE_NO_WINDOW must remove it.
	const script = `Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class KoneConsole { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'; [Console]::Write(([KoneConsole]::GetConsoleWindow() -ne [IntPtr]::Zero))`
	for _, runner := range []struct {
		name string
		run  commandRunner
	}{
		{name: "network configuration and restoration", run: runCommand},
		{name: "read-only DNS discovery", run: readDNSCommand},
	} {
		t.Run(runner.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			output, err := runner.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
			require.NoError(t, err)
			require.Equal(t, "False", string(output), "background PowerShell must not attach or create a console")
		})
	}
}

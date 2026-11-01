package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMacHelperPassesArgumentsAsDataAndAppleScriptCompiles(t *testing.T) {
	executable := "/Applications/Kone user's app/kone"
	args := []string{"-network-helper", "/private/tmp/kone-12345", "-parent-pid", "1234"}
	command := helperAuthorizationCommand(context.Background(), executable, args)
	require.Equal(t, "/usr/bin/osascript", command.Path)
	require.Equal(t, append([]string{"/usr/bin/osascript", "-e", helperAppleScript, "--", executable}, args...), command.Args)
	require.NotContains(t, helperAppleScript, executable)
	// Compile the exact script without executing it or requesting administrator
	// permission. This catches AppleScript syntax changes on the actual platform.
	output, err := exec.Command("/usr/bin/osacompile", "-o", t.TempDir()+"/helper.scpt", "-e", helperAppleScript).CombinedOutput()
	require.NoError(t, err, string(output))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, launchManagedHelper(ctx, executable, args), context.Canceled)
}

func TestMacQuotingDoesNotExecuteArgumentContents(t *testing.T) {
	script := strings.Split(helperAppleScript, "on run argv")[0] + "on run argv\nreturn my quotedCommand(argv)\nend run"
	value := "argument with ' quotes; $(printf unsafe) and spaces"
	output, err := exec.Command("/usr/bin/osascript", "-e", script, "--", "/usr/bin/printf", value).Output()
	require.NoError(t, err)
	// Run the interpreter-produced command as the ordinary test user. printf
	// receives the literal value; shell substitutions are never evaluated.
	result, err := exec.Command("/bin/sh", "-c", strings.TrimSpace(string(output))).Output()
	require.NoError(t, err)
	require.Equal(t, value, string(result))
}

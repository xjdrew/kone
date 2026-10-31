package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// AppleScript receives every value as an argv item and quotes it itself. The
// fixed redirection/background suffix detaches only this verified helper; no
// configuration, credential or user-provided shell fragment is interpolated.
const helperAppleScript = `on quotedCommand(tokens)
    set commandText to ""
    repeat with token in tokens
        if commandText is not "" then set commandText to commandText & " "
        set commandText to commandText & quoted form of (contents of token)
    end repeat
    return commandText
end quotedCommand
on run argv
    if (count of argv) < 1 then error "Missing helper executable"
    set commandText to my quotedCommand(argv)
    do shell script commandText & " </dev/null >/dev/null 2>&1 &" with administrator privileges
end run`

func helperAuthorizationCommand(ctx context.Context, executable string, args []string) *exec.Cmd {
	arguments := append([]string{"-e", helperAppleScript, "--", executable}, args...)
	command := exec.CommandContext(ctx, "/usr/bin/osascript", arguments...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	return command
}

func launchManagedHelper(ctx context.Context, executable string, args []string) error {
	if err := helperAuthorizationCommand(ctx, executable, args).Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("macOS administrator authorization did not complete: %w", err)
	}
	return nil
}

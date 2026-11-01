package application

import (
	"context"
	"io"
	"os/exec"
)

const startupAlertScript = `on run argv
    display alert (item 1 of argv) message (item 2 of argv) as critical buttons {"OK"} default button "OK"
end run`

func showDesktopFailure(code int) {
	showDesktopNotice("KONE startup failed", desktopFailureMessage(code))
}

func showDesktopNotice(heading, body string) {
	command := exec.Command("/usr/bin/osascript", "-e", startupAlertScript, "--", heading, body)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	_ = command.Run()
}

func elevateForDesktop(ctx context.Context, config string, debug bool, output io.Writer) (bool, error) {
	return elevateForWindows(ctx, config, debug, output)
}

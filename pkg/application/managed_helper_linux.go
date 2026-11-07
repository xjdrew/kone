package application

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"

	"github.com/xjdrew/kone/pkg/desktop"
)

func helperAuthorizationCommand(executable string, args []string) *exec.Cmd {
	// The registered desktop agent owns the password prompt. Never fall back
	// to reading a password from the management terminal or a Web request.
	arguments := append([]string{"--disable-internal-agent", executable}, args...)
	command := exec.Command("pkexec", arguments...)
	command.Stdin = nil
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = time.Second
	return command
}

func launchManagedHelper(ctx context.Context, executable string, args []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := helperAuthorizationCommand(executable, args).Run()
	if err == nil {
		return nil
	}
	code := "helper_start_failed"
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		switch exit.ExitCode() {
		case 126:
			code = "authorization_canceled"
		case 127:
			code = "authorization_failed"
		}
	}
	if errors.Is(err, exec.ErrNotFound) {
		code = "authorization_unavailable"
	}
	return &desktop.AuthorizationError{Code: code, Cause: err}
}

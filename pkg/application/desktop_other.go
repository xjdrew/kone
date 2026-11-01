//go:build !windows && !darwin

package application

import (
	"context"
	"io"
)

func showDesktopFailure(int, string) {}

func showDesktopNotice(string, string) {}

func showBrowserNotice(string, string) {}

func elevateForDesktop(ctx context.Context, config string, debug bool, output io.Writer) (bool, error) {
	return elevateForWindows(ctx, config, debug, output)
}

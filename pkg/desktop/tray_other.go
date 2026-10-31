//go:build !windows

package desktop

import (
	"context"
	"errors"
)

func TrayAvailable() bool { return false }
func RunTray(context.Context, TrayActions) error {
	return errors.New("native desktop tray is currently available on Windows only")
}

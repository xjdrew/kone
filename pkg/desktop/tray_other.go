//go:build !windows && !darwin

package desktop

import (
	"context"
	"errors"
)

func TrayAvailable() bool { return false }
func RunTray(context.Context, TrayActions) error {
	return errors.New("native desktop tray is unavailable on this platform")
}

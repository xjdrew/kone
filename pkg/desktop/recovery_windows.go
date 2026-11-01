package desktop

import (
	"context"
	"errors"
	"io"
)

// RecoverSystemDNS uses the same authenticated, owner-only named pipes as the
// capture helper but never constructs or starts a capture engine.
func RecoverSystemDNS(ctx context.Context, id string, launch LaunchHelper) error {
	if launch == nil {
		return errors.New("UAC recovery helper launcher is unavailable")
	}
	return recoverDNSWithConnector(ctx, id, func(ctx context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return connectWindows(ctx, launch)
	})
}

//go:build !windows

package desktop

import (
	"context"
	"errors"
)

func RecoverSystemDNS(context.Context, string, LaunchHelper) error {
	return errors.New("system DNS recovery helper is only available on Windows")
}

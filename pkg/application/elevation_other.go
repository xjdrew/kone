//go:build !windows

package application

import (
	"context"
	"io"
)

func elevateForWindows(context.Context, string, bool, io.Writer) (bool, error) {
	return false, nil
}

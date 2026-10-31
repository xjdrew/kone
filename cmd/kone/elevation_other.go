//go:build !windows

package main

import (
	"context"
	"io"
)

func elevateForWindows(context.Context, string, bool, io.Writer) (bool, error) {
	return false, nil
}

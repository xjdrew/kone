//go:build !linux && !windows && !darwin

package process

import (
	"context"
	"errors"
)

func Supported() bool { return false }
func lookupNative(context.Context, Query) (Result, error) {
	return Result{}, errors.New("process attribution unsupported on this platform")
}

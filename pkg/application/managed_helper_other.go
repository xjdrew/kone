//go:build !windows && !darwin

package application

import (
	"context"
	"errors"
)

func launchManagedHelper(context.Context, string, []string) error {
	return errors.New("privileged desktop helper is unavailable on this platform")
}

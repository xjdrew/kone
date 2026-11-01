package application

import (
	"context"
	"path/filepath"
)

func launchManagedHelper(ctx context.Context, executable string, args []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return launchElevated(elevationRequest{executable: executable, directory: filepath.Dir(executable), args: args, hidden: true})
}

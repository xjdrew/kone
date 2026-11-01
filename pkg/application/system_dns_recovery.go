package application

import "context"

func selectSystemDNSRecovery(ctx context.Context, id string, needsHelper func() bool, direct, helper func(context.Context, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if needsHelper() {
		return helper(ctx, id)
	}
	return direct(ctx, id)
}

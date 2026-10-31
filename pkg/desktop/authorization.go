package desktop

import (
	"context"
	"errors"
)

// An operating-system authorization dialog can outlive context cancellation.
// Keep its slot until the actual shell call returns, so retries cannot stack
// unbounded prompts. Canceled callers immediately abandon their private pipes.
var authorizationSlot = make(chan struct{}, 1)

func boundedAuthorization(ctx context.Context, launch func() error, slot chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case slot <- struct{}{}:
	default:
		return errors.New("a previous administrator authorization is still pending; finish or cancel that dialog before retrying")
	}
	result := make(chan error, 1)
	go func() { err := func() error { defer func() { <-slot }(); return launch() }(); result <- err }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

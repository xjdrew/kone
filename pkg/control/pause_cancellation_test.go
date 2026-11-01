package control

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

type delayedCleanupEngine struct {
	*memoryEngine
	release <-chan struct{}
}

func (engine *delayedCleanupEngine) Run(ctx context.Context) error {
	close(engine.ready)
	<-ctx.Done()
	<-engine.release
	return nil
}

func (engine *delayedCleanupEngine) Close() error { return nil }

func TestCanceledPauseKeepsCaptureLockedUntilCleanupActuallyFinishes(t *testing.T) {
	// Model an engine whose device cleanup is still finishing after it has
	// accepted cancellation. A timed-out UI operation must not claim capture
	// is paused or allow a second engine to start over those resources.
	release := make(chan struct{})
	var releaseOnce sync.Once
	finishCleanup := func() { releaseOnce.Do(func() { close(release) }) }
	var constructed atomic.Int32
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) {
		constructed.Add(1)
		return &delayedCleanupEngine{memoryEngine: newMemoryEngine(), release: release}, nil
	}})
	t.Cleanup(finishCleanup)
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, c.Pause(ctx), context.Canceled)
	require.Equal(t, "pausing", c.State().State)
	require.True(t, c.State().CaptureLocked)
	require.ErrorContains(t, c.Start(t.Context()), "already in progress")
	require.Equal(t, int32(1), constructed.Load())
	finishCleanup()
	require.Eventually(t, func() bool { return c.State().State == "paused" }, time.Second, time.Millisecond)
	require.False(t, c.State().CaptureLocked)
	require.NoFileExists(t, c.journalPath())
}

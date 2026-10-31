package desktop

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestUnresponsiveAuthorizationCannotBlockCancellationOrStackDialogs(t *testing.T) {
	slot := make(chan struct{}, 1)
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	entered := make(chan struct{})
	var calls atomic.Int32
	launch := func() error { calls.Add(1); close(entered); <-release; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- boundedAuthorization(ctx, launch, slot) }()
	<-entered
	started := time.Now()
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.Less(t, time.Since(started), time.Second, "a launcher ignoring context cannot retain the controller action lock")
	for range 10 {
		require.ErrorContains(t, boundedAuthorization(context.Background(), launch, slot), "still pending")
	}
	require.Equal(t, int32(1), calls.Load(), "timeouts do not permit another native authorization dialog")
	close(release)
	require.Eventually(t, func() bool { return len(slot) == 0 }, time.Second, time.Millisecond)
	require.NoError(t, boundedAuthorization(context.Background(), func() error { return nil }, slot))
}

func TestRemoteCloseCancelsAConnectorBlockedInAuthorization(t *testing.T) {
	slot := make(chan struct{}, 1)
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	entered := make(chan struct{})
	remote, err := NewRemote(kone.DefaultConfig(), func(ctx context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		err := boundedAuthorization(ctx, func() error { close(entered); <-release; return nil }, slot)
		return nil, nil, err
	})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- remote.Run(context.Background()) }()
	<-entered
	require.NoError(t, remote.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("RemoteEngine.Close waited for an unresponsive authorization dialog")
	}
	close(release)
}

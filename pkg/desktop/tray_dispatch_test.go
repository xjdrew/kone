package desktop

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTrayRepeatedActionsCoalesceWithoutQueueing(t *testing.T) {
	var starts atomic.Int32
	var exits atomic.Int32
	started := make(chan struct{}, 2)
	exited := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	actions := prepareTrayActions(TrayActions{
		Start: func() { starts.Add(1); started <- struct{}{}; <-release },
		Exit:  func() { exits.Add(1); exited <- struct{}{}; <-release },
	})
	invokeTrayAction(actions, 4)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("start callback did not run asynchronously")
	}
	var callers sync.WaitGroup
	for range 128 {
		callers.Add(1)
		go func() { defer callers.Done(); invokeTrayAction(actions, 4) }()
	}
	callers.Wait()
	require.Equal(t, int32(1), starts.Load(), "repeated clicks must not queue another future capture")
	invokeTrayAction(actions, 3)
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("exit must remain available while start waits for authorization")
	}
	for range 128 {
		invokeTrayAction(actions, 3)
	}
	require.Equal(t, int32(1), exits.Load())
	releaseOnce.Do(func() { close(release) })
	require.Eventually(t, func() bool { return !actions.dispatch.active[4].Load() && !actions.dispatch.active[3].Load() }, time.Second, time.Millisecond)
	require.Equal(t, int32(1), starts.Load(), "merged clicks must be discarded rather than replayed after completion")
	invokeTrayAction(actions, 4)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("a completed action must release its slot for a new explicit click")
	}
	require.Equal(t, int32(2), starts.Load())
}

func TestTrayActionSlotsBelongToEachInstance(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	var calls atomic.Int32
	action := func() { calls.Add(1); <-blocked }
	first := prepareTrayActions(TrayActions{Open: action})
	second := prepareTrayActions(TrayActions{Open: action})
	invokeTrayAction(first, 1)
	invokeTrayAction(second, 1)
	require.Eventually(t, func() bool { return calls.Load() == 2 }, time.Second, time.Millisecond)
	invokeTrayAction(first, 0)
	invokeTrayAction(first, 99)
	invokeTrayAction(first, 2) // A missing action must not acquire a slot.
	require.False(t, first.dispatch.active[2].Load())
}

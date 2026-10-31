package control

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNetworkWatchStopsOnChangesWithoutMutatingHost(t *testing.T) {
	for _, changed := range []string{"interfaces", "dns", "routes"} {
		t.Run(changed, func(t *testing.T) {
			calls := 0
			changes := watchNetworkChanges(context.Background(), time.Millisecond, func(context.Context) (networkFingerprint, error) {
				calls++
				result := networkFingerprint{interfaces: "interfaces", dns: "dns", routes: "routes"}
				if calls > 1 {
					switch changed {
					case "interfaces":
						result.interfaces = "new"
					case "dns":
						result.dns = "new"
					case "routes":
						result.routes = "new"
					}
				}
				return result, nil
			})
			select {
			case event := <-changes:
				require.Equal(t, "environment_changed", event.Kind)
				require.Equal(t, []string{changed}, event.Changed)
				require.Empty(t, event.Error)
			case <-time.After(time.Second):
				t.Fatal("change was not reported")
			}
			_, open := <-changes
			require.False(t, open)
		})
	}
}

func TestNetworkWatchReportsReadFailureAndHonorsCancel(t *testing.T) {
	changes := watchNetworkChanges(context.Background(), time.Millisecond, func(context.Context) (networkFingerprint, error) {
		return networkFingerprint{}, errors.New("private system details")
	})
	event := <-changes
	require.Equal(t, "inspection_failed", event.Kind)
	require.NotContains(t, event.Error, "private")
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	changes = watchNetworkChanges(ctx, time.Millisecond, func(context.Context) (networkFingerprint, error) { calls.Add(1); return networkFingerprint{}, nil })
	require.Eventually(t, func() bool { return calls.Load() > 1 }, time.Second, time.Millisecond)
	cancel()
	select {
	case _, open := <-changes:
		require.False(t, open, "normal shutdown must not be reported as a network failure")
	case <-time.After(time.Second):
		t.Fatal("network watcher ignored cancellation")
	}
}

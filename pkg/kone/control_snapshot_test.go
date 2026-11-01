package kone

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	processinfo "github.com/xjdrew/kone/pkg/process"
)

func TestFrozenObservationKeepsSampleTimeAndExpiresPrivateDetails(t *testing.T) {
	now := time.Unix(100, 100_000_000)
	observer := NewTrafficObserver(ObservationOptions{Now: func() time.Time { return now }, Retention: 5 * time.Second})
	flow := observer.Begin(FlowRecord{Protocol: "tcp", Target: "private.example:443", Source: "192.0.2.1:1234"})
	flow.Decision(RoutingDecision{RuleID: "test-rule", Outbound: BuiltinDirect}, BuiltinDirect, "192.0.2.2:443", true)
	flow.AddUpload(128, 1)
	flow.AddDownload(256, 1)
	flow.Finish(nil, false)
	live, _ := observer.Data(TrafficQuery{}, SankeyOptions{Window: time.Second})
	require.False(t, live.Frozen)
	now = now.Add(time.Second)
	observer.freeze()
	first, firstGraph := observer.Data(TrafficQuery{}, SankeyOptions{Window: time.Second})
	require.True(t, first.Frozen)
	require.True(t, firstGraph.Frozen)
	require.Equal(t, now, first.Timestamp)
	require.Equal(t, first.Timestamp, firstGraph.Timestamp)
	require.Equal(t, float64(128), first.Totals.UploadRate)
	require.Equal(t, float64(384), firstGraph.Total)
	now = now.Add(3 * time.Second)
	observer.freeze() // Idempotent: polling cannot refresh the historical time.
	flow.Process(processinfo.Result{Status: "matched", Name: "late-process"})
	flow.UpdateTarget("late.example", "198.18.1.2", "late.example:443")
	flow.Stage("late-stage")
	flow.Decision(RoutingDecision{RuleID: "late-rule"}, "late-outbound", "", false)
	flow.TransferError(errors.New("late-error"))
	flow.AddDownload(999, 1)
	late := observer.Begin(FlowRecord{Target: "new-after-stop.example"})
	late.AddUpload(1000, 1)
	late.Finish(nil, false)
	second, secondGraph := observer.Data(TrafficQuery{}, SankeyOptions{Window: time.Second})
	require.Equal(t, first, second)
	require.Equal(t, firstGraph, secondGraph)
	now = now.Add(3 * time.Second)
	expired, expiredGraph := observer.Data(TrafficQuery{}, SankeyOptions{Metric: "cumulative"})
	require.True(t, expired.Frozen)
	require.Equal(t, first.Timestamp, expired.Timestamp)
	require.Empty(t, expired.Records, "privacy expiry must use real elapsed time after sampling stops")
	require.Equal(t, uint64(384), expired.Totals.Bytes)
	require.Equal(t, float64(384), expiredGraph.Total)
	encoded, err := json.Marshal(expiredGraph)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "private.example")
	require.NotContains(t, string(encoded), "192.0.2.1")
	require.NotContains(t, string(encoded), "test-rule")
	observer.Clear()
	cleared, graph := observer.Data(TrafficQuery{}, SankeyOptions{Metric: "cumulative"})
	require.True(t, cleared.Frozen)
	require.Equal(t, first.Timestamp, cleared.Timestamp)
	require.Empty(t, cleared.Records)
	require.Equal(t, float64(384), graph.Total)
}

func TestStoppingLocalEngineFreezesOnlyAfterCleanup(t *testing.T) {
	network, sockets := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, network, sockets)
	observer := NewTrafficObserver(ObservationOptions{})
	require.NoError(t, one.SetTrafficObserver(observer))
	cancel, done := runReady(t, one)
	observer.SetRecording(false)
	traffic, graph, err := one.TrafficData(TrafficQuery{}, SankeyOptions{})
	require.NoError(t, err)
	require.False(t, traffic.Frozen, "recording preference is independent of lifecycle freeze")
	require.False(t, graph.Frozen)
	cancel()
	require.NoError(t, waitRun(t, done))
	traffic, graph, err = one.TrafficData(TrafficQuery{}, SankeyOptions{})
	require.NoError(t, err)
	require.True(t, traffic.Frozen)
	require.True(t, graph.Frozen)
	stoppedAt := traffic.Timestamp
	require.Equal(t, graph.Timestamp, stoppedAt)
	require.NoError(t, one.Close())
	second, secondGraph, err := one.TrafficData(TrafficQuery{}, SankeyOptions{})
	require.NoError(t, err)
	require.Equal(t, stoppedAt, second.Timestamp)
	require.Equal(t, stoppedAt, secondGraph.Timestamp)
	assertReleased(t, network, sockets)
}

func TestClosingUnstartedLocalEngineFreezesItsObservation(t *testing.T) {
	one := lifecycleEngine(t, newMemoryNetwork(), &loopSockets{})
	require.NoError(t, one.Close())
	traffic, graph, err := one.TrafficData(TrafficQuery{}, SankeyOptions{})
	require.NoError(t, err)
	require.True(t, traffic.Frozen)
	require.True(t, graph.Frozen)
	require.False(t, traffic.Timestamp.IsZero())
	require.Equal(t, traffic.Timestamp, graph.Timestamp)
	// A canceled start of an already closed engine cannot thaw the snapshot.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, one.Run(ctx))
	require.Equal(t, traffic.Timestamp, one.TrafficSnapshot(TrafficQuery{}).Timestamp)
}

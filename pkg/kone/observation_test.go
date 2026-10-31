package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type observationClock struct{ nano atomic.Int64 }

func newObservationClock() *observationClock {
	c := &observationClock{}
	c.nano.Store(time.Unix(1000, 0).UnixNano())
	return c
}
func (c *observationClock) now() time.Time          { return time.Unix(0, c.nano.Load()) }
func (c *observationClock) advance(d time.Duration) { c.nano.Add(int64(d)) }

func beginObserved(t *testing.T, o *TrafficObserver, target, protocol string) *ObservedFlow {
	t.Helper()
	f := o.Begin(FlowRecord{Protocol: protocol, Inbound: "tun", Source: "192.0.2.2:1234", Destination: "10.192.0.8:443", Target: target, ConfigVersion: 7})
	f.Decision(RoutingDecision{RuleID: "r1", RuleName: "Example rule", RuleSource: "config", RuleOrder: 1, Outbound: "office"}, "office", "", true)
	f.Stage("transfer")
	return f
}

func TestLiveObservationAndSankeyConservation(t *testing.T) {
	clock := newObservationClock()
	observer := NewTrafficObserver(ObservationOptions{Now: clock.now})
	flow := beginObserved(t, observer, "example.com:443", "tcp")
	flow.AddUpload(100, 0)
	flow.AddDownload(20, 0)
	live := observer.Snapshot(TrafficQuery{})
	require.Equal(t, uint64(1), live.Totals.Active)
	require.Equal(t, uint64(120), live.Totals.Bytes)
	require.Equal(t, "active", live.Records[0].Status)
	require.Equal(t, "unknown", live.Records[0].ProcessStatus)
	require.Empty(t, live.Records[0].RealDestination, "proxy peer is not the remote business address")
	clock.advance(time.Second)
	graph := observer.Sankey(TrafficQuery{}, SankeyOptions{})
	require.Equal(t, float64(120), graph.Total)
	require.Equal(t, "bytes/s", graph.Unit)
	require.Len(t, graph.Paths, 1)
	require.Equal(t, []string{flow.ID()}, graph.Paths[0].Filter.FlowIDs)
	for column := 0; column < 3; column++ {
		var sum float64
		columns := map[string]int{}
		for _, node := range graph.Nodes {
			columns[node.ID] = node.Column
		}
		for _, link := range graph.Links {
			if columns[link.Source] == column {
				sum += link.Value
			}
		}
		require.Equal(t, graph.Total, sum, "every layer projects the same business volume once")
	}
	page := observer.Snapshot(graph.Paths[0].Filter)
	require.Len(t, page.Records, 1)
	require.Equal(t, flow.ID(), page.Records[0].ID)
	copyRecord := page.Records[0]
	copyRecord.Target = "mutated"
	current, ok := observer.Get(flow.ID())
	require.True(t, ok)
	require.Equal(t, "example.com:443", current.Target)
	flow.Finish(nil, false)
	flow.Finish(errors.New("duplicate close"), false)
	zero := observer.Begin(FlowRecord{Target: "blocked.example:443", Protocol: "udp"})
	zero.Decision(RoutingDecision{RuleID: "r2", RuleName: "Blocked", Outbound: BuiltinReject}, BuiltinReject, "", false)
	zero.Finish(ErrRejected, false)
	graph = observer.Sankey(TrafficQuery{}, SankeyOptions{Metric: "cumulative"})
	require.Equal(t, float64(120), graph.Total)
	require.Equal(t, uint64(1), graph.Failures)
	for _, path := range graph.Paths {
		if path.Failures > 0 {
			require.Zero(t, path.Value, "zero-byte failures never manufacture bandwidth")
		}
	}
	final := observer.Snapshot(TrafficQuery{})
	require.Zero(t, final.Totals.Active)
	require.Equal(t, uint64(1), final.Totals.Closed)
	require.Equal(t, uint64(1), final.Totals.Rejected)
}

func TestObservationBoundsRetentionPrivacyAndPagination(t *testing.T) {
	clock := newObservationClock()
	observer := NewTrafficObserver(ObservationOptions{Capacity: 2, PathCapacity: 1, Retention: time.Minute, Now: clock.now})
	for index := 0; index < 3; index++ {
		flow := beginObserved(t, observer, fmt.Sprintf("target-%d:443", index), "udp")
		flow.AddUpload(10, 1)
		flow.Finish(nil, false)
	}
	snapshot := observer.Snapshot(TrafficQuery{Limit: 1})
	require.Len(t, snapshot.Records, 1)
	require.Equal(t, 2, snapshot.Total)
	require.Equal(t, uint64(1), snapshot.DroppedDetails)
	require.Equal(t, uint64(30), snapshot.Totals.Upload)
	require.True(t, snapshot.Truncated)
	graph := observer.Sankey(TrafficQuery{}, SankeyOptions{Metric: "cumulative", Limit: 1})
	require.Equal(t, float64(30), graph.Total)
	require.Len(t, graph.Paths, 1)
	require.True(t, graph.Paths[0].Other)
	anchor := snapshot.Anchor
	cursor := snapshot.NextCursor
	later := beginObserved(t, observer, "later:443", "tcp")
	next := observer.Snapshot(TrafficQuery{Anchor: anchor, Cursor: cursor, Limit: 1})
	for _, record := range next.Records {
		require.NotEqual(t, later.ID(), record.ID)
	}
	invalid := observer.Snapshot(TrafficQuery{Anchor: "other-session-123"})
	require.True(t, invalid.AnchorExpired)
	require.Empty(t, invalid.Records)
	later.Finish(nil, false)
	observer.Clear()
	require.Empty(t, observer.Snapshot(TrafficQuery{}).Records)
	require.Equal(t, float64(30), observer.Sankey(TrafficQuery{}, SankeyOptions{Metric: "cumulative"}).Total)
	observer.SetRecording(false)
	hidden := observer.Begin(FlowRecord{Target: "private.example"})
	hidden.AddDownload(5, 0)
	hidden.Finish(nil, false)
	require.Empty(t, observer.Snapshot(TrafficQuery{}).Records)
	require.Equal(t, uint64(35), observer.Snapshot(TrafficQuery{}).Totals.Bytes)
	observer.SetRecording(true)
	expiring := beginObserved(t, observer, "expiring:443", "tcp")
	expiring.Finish(nil, false)
	record, _ := observer.Get(expiring.ID())
	*record.EndedAt = time.Unix(0, 0)
	stored, _ := observer.Get(expiring.ID())
	require.NotEqual(t, time.Unix(0, 0), *stored.EndedAt)
	clock.advance(2 * time.Minute)
	require.Empty(t, observer.Snapshot(TrafficQuery{}).Records)
	require.True(t, observer.Snapshot(TrafficQuery{Anchor: anchor}).AnchorExpired)
}

func TestObservationFiltersRedactionAndConcurrentAccounting(t *testing.T) {
	clock := newObservationClock()
	observer := NewTrafficObserver(ObservationOptions{Now: clock.now})
	var workers sync.WaitGroup
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			flow := beginObserved(t, observer, "example.com:443", "udp")
			for range 100 {
				flow.AddUpload(2, 1)
				flow.AddDownload(3, 1)
			}
			flow.Finish(nil, false)
		}()
	}
	for range 20 {
		_ = observer.Snapshot(TrafficQuery{Protocol: "udp"})
		_ = observer.Sankey(TrafficQuery{}, SankeyOptions{Metric: "cumulative"})
	}
	workers.Wait()
	snapshot := observer.Snapshot(TrafficQuery{Protocol: "udp", Outbound: "office", RuleID: "r1", Inbound: "tun", Target: "example", Source: "192.0.2.2"})
	require.Equal(t, 20, snapshot.Total)
	require.Equal(t, uint64(4000), snapshot.Totals.Upload)
	require.Equal(t, uint64(6000), snapshot.Totals.Download)
	require.Equal(t, uint64(2000), snapshot.Totals.UploadPackets)
	require.Equal(t, uint64(2000), snapshot.Totals.DownloadPackets)
	failure := observer.Begin(FlowRecord{Target: "failure.example", Protocol: "tcp"})
	failure.Finish(errors.New("dial https://user:password@proxy.example:443 failed\nnext"), false)
	record, _ := observer.Get(failure.ID())
	require.NotContains(t, record.Error, "password")
	require.NotContains(t, record.Error, "\n")
	require.Len(t, observer.Snapshot(TrafficQuery{Status: "failed", FlowIDs: []string{failure.ID()}}).Records, 1)
	require.Empty(t, observer.Snapshot(TrafficQuery{Protocol: "icmp"}).Records)
	cleanProxyEnv(t)
	one := testEngine(t)
	require.NoError(t, one.SetTrafficObserver(observer))
	require.Same(t, observer, one.TrafficObserver())
	require.Error(t, one.SetTrafficObserver(nil))
	require.NoError(t, one.Close())
	require.Error(t, one.SetTrafficObserver(observer))
}

func TestObservedConnectionCountsForwardedWritesAndHalfClose(t *testing.T) {
	observer := NewTrafficObserver(ObservationOptions{})
	flow := beginObserved(t, observer, "local:80", "tcp")
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	observed := &observedConn{Conn: left, flow: flow, upload: true}
	done := make(chan error, 1)
	go func() { _, err := observed.Write([]byte("ping")); done <- err }()
	data := make([]byte, 4)
	_, err := right.Read(data)
	require.NoError(t, err)
	require.NoError(t, <-done)
	record, _ := observer.Get(flow.ID())
	require.Equal(t, uint64(4), record.Upload)
	require.NoError(t, observed.CloseWrite())
	flow.Finish(context.Canceled, true)
	record, _ = observer.Get(flow.ID())
	require.Equal(t, "canceled", record.Status)
}

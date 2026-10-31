package desktop

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestFrozenArchiveExpiresOnlyOldEvidenceAndKeepsMeasuredTotals(t *testing.T) {
	now := time.Now()
	clock := now.Add(-70 * time.Second)
	observer := kone.NewTrafficObserver(kone.ObservationOptions{Now: func() time.Time { return clock }, Retention: time.Minute})
	add := func(target string, size uint64) *kone.ObservedFlow {
		flow := observer.Begin(kone.FlowRecord{Protocol: "tcp", Source: "192.0.2.1:1234", Target: target})
		flow.Decision(kone.RoutingDecision{RuleID: "r1", Outbound: kone.BuiltinDirect}, kone.BuiltinDirect, "", true)
		flow.AddUpload(size, 0)
		flow.Finish(nil, false)
		return flow
	}
	old := add("old-private.example:443", 10)
	clock = now.Add(-40 * time.Second)
	fresh := add("fresh.example:443", 20)
	clock = now.Add(-30 * time.Second)
	traffic, graph := observer.Data(kone.TrafficQuery{}, kone.SankeyOptions{Metric: "cumulative"})
	remote := &RemoteEngine{closed: true, archive: &StopReply{Traffic: TrafficReply{Traffic: traffic, Sankey: graph}, Cumulative: graph, DNS: DNSReply{Status: kone.DNSRuntimeStatus{HistoryRetentionSeconds: 60}, Queries: []kone.DNSQueryEvent{{Name: "old-private.example", Time: now.Add(-70 * time.Second)}, {Name: "fresh.example", Time: now.Add(-40 * time.Second)}}}}}
	result, projected, err := remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{Metric: "cumulative"})
	require.NoError(t, err)
	require.Equal(t, uint64(30), result.Totals.Bytes)
	require.Equal(t, float64(30), projected.Total)
	require.Len(t, result.Records, 1)
	require.Equal(t, fresh.ID(), result.Records[0].ID)
	require.True(t, result.Frozen)
	require.Equal(t, traffic.Timestamp, result.Timestamp, "frozen evidence must not be restamped as current")
	_, ok, err := remote.FlowRecord(old.ID())
	require.NoError(t, err)
	require.False(t, ok)
	_, queries, err := remote.DNSData()
	require.NoError(t, err)
	require.Len(t, queries, 1)
	require.Equal(t, "fresh.example", queries[0].Name)
	encoded, err := json.Marshal(projected)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "old-private.example")
	for column := 0; column < 3; column++ {
		sum := float64(0)
		columns := map[string]int{}
		for _, node := range projected.Nodes {
			columns[node.ID] = node.Column
		}
		for _, link := range projected.Links {
			if columns[link.Source] == column {
				sum += link.Value
			}
		}
		require.Equal(t, projected.Total, sum, "anonymous expiry still conserves every layer")
	}
	require.NoError(t, remote.ClearObservation())
	result, projected, err = remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{Metric: "cumulative"})
	require.NoError(t, err)
	require.Empty(t, result.Records)
	require.Equal(t, float64(30), projected.Total)
	_, queries, err = remote.DNSData()
	require.NoError(t, err)
	require.Empty(t, queries)
}

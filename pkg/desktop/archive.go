package desktop

import (
	"fmt"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
)

// Cached totals survive a pause, while expired/cleared targets, source addresses
// and process identities do not. Immutable replacement keeps concurrent readers
// from observing a partially redacted archive.
func anonymousArchive(source *StopReply, clearDNS bool) *StopReply {
	copy := cloneDesktopValue(*source)
	traffic := &copy.Traffic.Traffic
	traffic.DroppedDetails += uint64(len(traffic.Records))
	traffic.Records = []kone.FlowRecord{}
	traffic.Total, traffic.NextCursor = 0, ""
	traffic.Truncated, traffic.AnchorExpired = true, true
	copy.Traffic.Sankey = anonymousGraph(copy.Traffic.Sankey)
	copy.Cumulative = anonymousGraph(copy.Cumulative)
	if clearDNS {
		copy.DNS.Queries = []kone.DNSQueryEvent{}
		copy.DNS.Status.CacheEntries = 0
	}
	return &copy
}

func anonymousGraph(graph kone.SankeySnapshot) kone.SankeySnapshot {
	var connections uint64
	for _, path := range graph.Paths {
		connections += path.Connections
	}
	graph.Truncated, graph.AnchorExpired = true, true
	graph.Nodes = []kone.SankeyNode{}
	graph.Links = []kone.SankeyLink{}
	path := kone.SankeyPath{ID: "other:unretained", Inbound: "other", RuleID: "other", RuleName: "Unretained history", EffectiveOutbound: "other", Target: "other", Value: graph.Total, Upload: graph.Upload, Download: graph.Download, Failures: graph.Failures, Connections: connections, Other: true}
	for index, kind := range []string{"inbound", "rule", "outbound", "destination"} {
		graph.Nodes = append(graph.Nodes, kone.SankeyNode{ID: "unretained:" + kind, Label: "Unretained history", Kind: kind, Column: index})
	}
	for index := 0; index < 3; index++ {
		graph.Links = append(graph.Links, kone.SankeyLink{ID: fmt.Sprintf("unretained:%d", index), Source: graph.Nodes[index].ID, Target: graph.Nodes[index+1].ID, Value: graph.Total, PathIDs: []string{path.ID}})
	}
	graph.Paths = []kone.SankeyPath{path}
	return graph
}

func (e *RemoteEngine) cachedArchive() (*StopReply, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	archive := e.archive
	if e.closed && archive != nil {
		now := time.Now()
		traffic := archive.Traffic.Traffic
		if !e.archiveAnonymous && traffic.RetentionSeconds > 0 {
			cutoff := now.Add(-time.Duration(traffic.RetentionSeconds) * time.Second)
			copy := *archive
			changed := false
			var kept []kone.FlowRecord
			for _, record := range traffic.Records {
				ended := record.UpdatedAt
				if record.EndedAt != nil {
					ended = *record.EndedAt
				}
				if !ended.Before(cutoff) {
					kept = append(kept, record)
				}
			}
			if len(kept) != len(traffic.Records) {
				changed = true
				copy.Traffic.Traffic.Records = kept
				copy.Traffic.Traffic.Total = len(kept)
				copy.Traffic.Traffic.NextCursor = ""
				copy.Traffic.Traffic.DroppedDetails += uint64(len(traffic.Records) - len(kept))
				copy.Traffic.Traffic.Truncated, copy.Traffic.Traffic.AnchorExpired = true, true
			}
			var pruned bool
			copy.Traffic.Sankey, pruned = copy.Traffic.Sankey.WithoutExpiredDetails(cutoff)
			changed = changed || pruned
			copy.Cumulative, pruned = copy.Cumulative.WithoutExpiredDetails(cutoff)
			changed = changed || pruned
			if changed {
				archive = &copy
			}
		}
		if retention := archive.DNS.Status.HistoryRetentionSeconds; retention > 0 && len(archive.DNS.Queries) > 0 {
			var kept []kone.DNSQueryEvent
			for _, event := range archive.DNS.Queries {
				if now.Before(event.Time.Add(time.Duration(retention) * time.Second)) {
					kept = append(kept, event)
				}
			}
			if len(kept) != len(archive.DNS.Queries) {
				copy := *archive
				copy.DNS = cloneDesktopValue(archive.DNS)
				copy.DNS.Queries = kept
				archive = &copy
			}
		}
		e.archive = archive
	}
	return archive, e.closed
}

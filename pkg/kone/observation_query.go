package kone

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (o *TrafficObserver) sequenceOf(id string) (uint64, bool) {
	prefix := o.session + "-"
	if !strings.HasPrefix(id, prefix) {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(id, prefix), 10, 64)
	return value, err == nil && value <= o.sequence
}

func matchesTraffic(record *FlowRecord, query TrafficQuery) bool {
	if len(query.FlowIDs) > 0 {
		found := false
		for _, id := range query.FlowIDs {
			if id == record.ID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if query.Protocol != "" && !strings.EqualFold(query.Protocol, record.Protocol) {
		return false
	}
	if query.Status != "" && query.Status != record.Status {
		return false
	}
	if query.Outbound != "" && query.Outbound != record.EffectiveOutbound && query.Outbound != record.ExpectedOutbound && query.Outbound != record.AttemptedOutbound {
		return false
	}
	if query.RuleID != "" && query.RuleID != record.RuleID {
		return false
	}
	if query.Inbound != "" && query.Inbound != record.Inbound {
		return false
	}
	if query.Source != "" && !strings.Contains(strings.ToLower(record.Source), strings.ToLower(query.Source)) {
		return false
	}
	if query.Target != "" && !strings.Contains(strings.ToLower(record.Target+" "+record.Destination+" "+record.Domain+" "+record.RealDestination), strings.ToLower(query.Target)) {
		return false
	}
	if !query.Until.IsZero() && record.StartedAt.After(query.Until) {
		return false
	}
	if !query.Since.IsZero() && record.EndedAt != nil && record.EndedAt.Before(query.Since) {
		return false
	}
	if len(query.PathIDs) > 0 {
		found := false
		for _, id := range query.PathIDs {
			if record.pathID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func cloneFlowRecord(record FlowRecord) FlowRecord {
	if record.ProcessObservedAt != nil {
		value := *record.ProcessObservedAt
		record.ProcessObservedAt = &value
	}
	if record.ProcessStartedAt != nil {
		value := *record.ProcessStartedAt
		record.ProcessStartedAt = &value
	}
	if record.EndedAt != nil {
		value := *record.EndedAt
		record.EndedAt = &value
	}
	return record
}

func (o *TrafficObserver) Snapshot(query TrafficQuery) TrafficSnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.snapshotLocked(query, o.now())
}

func (o *TrafficObserver) snapshotLocked(query TrafficQuery, now time.Time) TrafficSnapshot {
	o.prune(now)
	anchor := o.sequence
	if query.Anchor != "" {
		parsed, ok := o.sequenceOf(query.Anchor)
		if !ok {
			result := o.emptySnapshot(now, query.Anchor)
			result.AnchorExpired = true
			result.Truncated = true
			return result
		}
		anchor = parsed
	}
	before := uint64(0)
	if query.Cursor != "" {
		parsed, ok := o.sequenceOf(query.Cursor)
		if !ok {
			result := o.emptySnapshot(now, query.Anchor)
			result.AnchorExpired = true
			result.Truncated = true
			return result
		}
		before = parsed
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	result := o.emptySnapshot(now, fmt.Sprintf("%s-%020d", o.session, anchor))
	if query.Anchor != "" && anchor > 0 && o.recording && (len(o.order) == 0 || o.records[o.order[0]].sequence > anchor) {
		result.AnchorExpired = true
		result.Truncated = true
	}
	for index := len(o.order) - 1; index >= 0; index-- {
		record := o.records[o.order[index]]
		if record == nil || record.sequence > anchor || !matchesTraffic(record, query) {
			continue
		}
		result.Total++
		if before > 0 && record.sequence >= before {
			continue
		}
		if len(result.Records) < limit {
			result.Records = append(result.Records, cloneFlowRecord(*record))
		} else if result.NextCursor == "" && len(result.Records) > 0 {
			result.NextCursor = result.Records[len(result.Records)-1].ID
		}
	}
	return result
}

func (o *TrafficObserver) emptySnapshot(now time.Time, anchor string) TrafficSnapshot {
	totals := o.totals
	totals.Bytes = totals.Upload
	addCounter(&totals.Bytes, totals.Download)
	end := now.Truncate(time.Second)
	counts := o.windowCounts(end.Add(-time.Second), end)
	totals.UploadRate, totals.DownloadRate = float64(counts.Upload), float64(counts.Download)
	return TrafficSnapshot{SessionID: o.session, StartedAt: o.started, Timestamp: now, Scope: TrafficScope, Totals: totals, Records: []FlowRecord{}, Anchor: anchor, Capacity: o.capacity, RetentionSeconds: int64(o.retention / time.Second), DroppedDetails: o.dropped, Recording: o.recording, Truncated: o.dropped > 0}
}

func (o *TrafficObserver) Get(id string) (FlowRecord, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.prune(o.now())
	record, ok := o.records[id]
	if !ok {
		return FlowRecord{}, false
	}
	return cloneFlowRecord(*record), true
}

func (o *TrafficObserver) WindowDurations() []time.Duration {
	return []time.Duration{time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second}
}

func (o *TrafficObserver) windowCounts(since, until time.Time) pathCounts {
	var result pathCounts
	for _, bucket := range o.buckets {
		if bucket.second < since.Unix() || bucket.second >= until.Unix() {
			continue
		}
		addCounter(&result.Upload, bucket.counts.Upload)
		addCounter(&result.Download, bucket.counts.Download)
		addCounter(&result.Connections, bucket.counts.Connections)
		addCounter(&result.Failures, bucket.counts.Failures)
	}
	return result
}

func sortPaths(paths []SankeyPath) {
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Value != paths[j].Value {
			return paths[i].Value > paths[j].Value
		}
		return paths[i].ID < paths[j].ID
	})
}

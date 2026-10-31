package kone

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type SankeyOptions struct {
	Window time.Duration
	Metric string
	Limit  int
}

type SankeyNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Column int    `json:"column"`
}

type SankeyLink struct {
	ID      string   `json:"id"`
	Source  string   `json:"source"`
	Target  string   `json:"target"`
	Value   float64  `json:"value"`
	PathIDs []string `json:"path_ids"`
}

type SankeyPath struct {
	ID                string       `json:"id"`
	Inbound           string       `json:"inbound"`
	Source            string       `json:"source,omitempty"`
	RuleID            string       `json:"rule_id"`
	RuleName          string       `json:"rule_name"`
	ConfigVersion     uint64       `json:"config_version"`
	Protocol          string       `json:"protocol"`
	ExpectedOutbound  string       `json:"expected_outbound"`
	EffectiveOutbound string       `json:"effective_outbound"`
	Target            string       `json:"target"`
	Value             float64      `json:"value"`
	Upload            uint64       `json:"upload"`
	Download          uint64       `json:"download"`
	Connections       uint64       `json:"connections"`
	Failures          uint64       `json:"failures"`
	Other             bool         `json:"other"`
	Filter            TrafficQuery `json:"filter"`
	LastSeen          time.Time    `json:"last_seen"`
}

type SankeySnapshot struct {
	Frozen        bool         `json:"frozen"`
	SessionID     string       `json:"session_id"`
	Timestamp     time.Time    `json:"timestamp"`
	Scope         string       `json:"scope"`
	Metric        string       `json:"metric"`
	Unit          string       `json:"unit"`
	WindowStart   time.Time    `json:"window_start"`
	WindowEnd     time.Time    `json:"window_end"`
	Total         float64      `json:"total"`
	Upload        uint64       `json:"upload"`
	Download      uint64       `json:"download"`
	Failures      uint64       `json:"failures"`
	Nodes         []SankeyNode `json:"nodes"`
	Links         []SankeyLink `json:"links"`
	Paths         []SankeyPath `json:"paths"`
	Anchor        string       `json:"anchor"`
	Truncated     bool         `json:"truncated"`
	AnchorExpired bool         `json:"anchor_expired"`
}

func stableTrafficID(prefix string, parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return prefix + hex.EncodeToString(digest[:12])
}

func (o *TrafficObserver) path(record *FlowRecord) string {
	if record.pathID != "" {
		return record.pathID
	}
	outbound := record.EffectiveOutbound
	if outbound == "" {
		if record.Status == "rejected" {
			outbound = "reject"
		} else if record.AttemptedOutbound != "" {
			outbound = "attempted:" + record.AttemptedOutbound
		} else {
			outbound = "not-connected"
		}
	}
	source := record.Source
	if host, _, err := net.SplitHostPort(source); err == nil {
		source = host
	}
	id := stableTrafficID("path-", record.Inbound, source, record.RuleID, fmt.Sprint(record.ConfigVersion), record.Protocol, record.ExpectedOutbound, outbound, record.Target)
	if _, ok := o.paths[id]; !ok {
		if len(o.paths) >= o.pathCapacity {
			id = "other"
		} else {
			o.paths[id] = &SankeyPath{ID: id, Inbound: record.Inbound, Source: source, RuleID: record.RuleID, RuleName: record.RuleName, ConfigVersion: record.ConfigVersion, Protocol: record.Protocol, ExpectedOutbound: record.ExpectedOutbound, EffectiveOutbound: outbound, Target: record.Target}
		}
	}
	record.pathID = id
	o.countPath(record.ID, id, 0, 0, 1, 0)
	return id
}

func (o *TrafficObserver) countPath(flowID, pathID string, upload, download, connections, failures uint64) {
	path := o.paths[pathID]
	if path == nil {
		path = o.paths["other"]
		if path == nil {
			path = &SankeyPath{ID: "other", Inbound: "other", RuleID: "other", RuleName: "Other / unretained details", EffectiveOutbound: "other", Target: "other", Other: true}
			o.paths["other"] = path
		}
	}
	addCounter(&path.Upload, upload)
	addCounter(&path.Download, download)
	addCounter(&path.Connections, connections)
	addCounter(&path.Failures, failures)
	path.LastSeen = o.now()
	second := o.now().Unix()
	index := (second%61 + 61) % 61
	bucket := &o.buckets[index]
	if bucket.second != second || bucket.paths == nil {
		*bucket = trafficBucket{second: second, paths: map[string]pathCounts{}, flows: map[string]pathCounts{}}
	}
	addCounts := func(counts *pathCounts) {
		addCounter(&counts.Upload, upload)
		addCounter(&counts.Download, download)
		addCounter(&counts.Connections, connections)
		addCounter(&counts.Failures, failures)
	}
	addCounts(&bucket.counts)
	counts := bucket.paths[path.ID]
	addCounts(&counts)
	bucket.paths[path.ID] = counts
	if _, exists := bucket.flows[flowID]; exists || len(bucket.flows) < 1024 {
		counts = bucket.flows[flowID]
		addCounts(&counts)
		bucket.flows[flowID] = counts
	} else {
		bucket.truncated = true
	}
}

func mergePathCount(destination *pathCounts, value pathCounts) {
	addCounter(&destination.Upload, value.Upload)
	addCounter(&destination.Download, value.Download)
	addCounter(&destination.Connections, value.Connections)
	addCounter(&destination.Failures, value.Failures)
}

func pathAsRecord(path *SankeyPath) *FlowRecord {
	return &FlowRecord{Inbound: path.Inbound, Source: path.Source, RuleID: path.RuleID, Protocol: path.Protocol, ExpectedOutbound: path.ExpectedOutbound, EffectiveOutbound: path.EffectiveOutbound, AttemptedOutbound: strings.TrimPrefix(path.EffectiveOutbound, "attempted:"), Target: path.Target, pathID: path.ID}
}

func (o *TrafficObserver) Sankey(query TrafficQuery, options SankeyOptions) SankeySnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sankeyLocked(query, options, o.now())
}

func (o *TrafficObserver) sankeyLocked(query TrafficQuery, options SankeyOptions, now time.Time) SankeySnapshot {
	o.prune(now)
	if !o.frozenAt.IsZero() {
		now = o.frozenAt
	}
	if options.Window < time.Second {
		options.Window = time.Second
	}
	if options.Window > time.Minute {
		options.Window = time.Minute
	}
	options.Window = options.Window.Truncate(time.Second)
	if options.Metric != "upload" && options.Metric != "download" && options.Metric != "cumulative" {
		options.Metric = "total"
	}
	if options.Limit <= 0 {
		options.Limit = 20
	}
	if options.Limit > 100 {
		options.Limit = 100
	}
	end := now.Truncate(time.Second)
	if !query.Until.IsZero() && query.Until.Before(end) {
		end = query.Until.Truncate(time.Second)
	}
	start := end.Add(-options.Window)
	if options.Metric == "cumulative" {
		start, end = o.started, now
	}
	result := SankeySnapshot{Frozen: !o.frozenAt.IsZero(), SessionID: o.session, Timestamp: now, Scope: TrafficScope, Metric: options.Metric, Unit: "bytes/s", WindowStart: start, WindowEnd: end, Nodes: []SankeyNode{}, Links: []SankeyLink{}, Paths: []SankeyPath{}, Anchor: fmt.Sprintf("%s-%020d", o.session, o.sequence), Truncated: o.dropped > 0 || !o.recording || o.paths["other"] != nil}
	if options.Metric == "cumulative" {
		result.Unit = "bytes"
	}
	anchor := o.sequence
	if query.Anchor != "" {
		parsed, ok := o.sequenceOf(query.Anchor)
		if !ok {
			result.AnchorExpired = true
			result.Truncated = true
			return result
		}
		anchor = parsed
		result.Anchor = query.Anchor
	}
	counts := map[string]pathCounts{}
	pathFlowIDs := map[string][]string{}
	if options.Metric == "cumulative" && query.Status == "" && query.Source == "" && len(query.FlowIDs) == 0 && query.Anchor == "" && query.Since.IsZero() && query.Until.IsZero() {
		for id, path := range o.paths {
			// These aggregates span the session. Apply categorical filters;
			// a historical interval requires sampled flow evidence below.
			candidate := query
			candidate.Since, candidate.Until = time.Time{}, time.Time{}
			if matchesTraffic(pathAsRecord(path), candidate) {
				counts[id] = pathCounts{Upload: path.Upload, Download: path.Download, Connections: path.Connections, Failures: path.Failures}
			}
		}
	} else {
		flowCounts := map[string]pathCounts{}
		var allWindow pathCounts
		if options.Metric == "cumulative" {
			for id, record := range o.records {
				if record.sequence <= anchor && matchesTraffic(record, query) {
					flowCounts[id] = pathCounts{Upload: record.Upload, Download: record.Download, Connections: 1, Failures: boolCounter(record.Status == "failed" || record.Status == "rejected")}
				}
			}
		} else {
			for _, bucket := range o.buckets {
				if bucket.second < start.Unix() || bucket.second >= end.Unix() {
					continue
				}
				mergePathCount(&allWindow, bucket.counts)
				if bucket.truncated {
					result.Truncated = true
				}
				for id, value := range bucket.flows {
					count := flowCounts[id]
					mergePathCount(&count, value)
					flowCounts[id] = count
				}
			}
		}
		var accounted pathCounts
		for id, count := range flowCounts {
			record := o.records[id]
			if record == nil {
				result.Truncated = true
				continue
			}
			if record.sequence > anchor || !matchesTraffic(record, query) {
				continue
			}
			pathID := record.pathID
			if pathID == "" {
				continue
			}
			value := counts[pathID]
			mergePathCount(&value, count)
			counts[pathID] = value
			pathFlowIDs[pathID] = append(pathFlowIDs[pathID], id)
			mergePathCount(&accounted, count)
		}
		if options.Metric != "cumulative" && query.Protocol == "" && query.Status == "" && query.Outbound == "" && query.RuleID == "" && query.Inbound == "" && query.Target == "" && query.Source == "" && len(query.PathIDs) == 0 && len(query.FlowIDs) == 0 && query.Anchor == "" {
			missing := pathCounts{}
			if allWindow.Upload >= accounted.Upload {
				missing.Upload = allWindow.Upload - accounted.Upload
			}
			if allWindow.Download >= accounted.Download {
				missing.Download = allWindow.Download - accounted.Download
			}
			if allWindow.Failures >= accounted.Failures {
				missing.Failures = allWindow.Failures - accounted.Failures
			}
			if allWindow.Connections >= accounted.Connections {
				missing.Connections = allWindow.Connections - accounted.Connections
			}
			if missing.Upload != 0 || missing.Download != 0 || missing.Failures != 0 || missing.Connections != 0 {
				value := counts["other"]
				mergePathCount(&value, missing)
				counts["other"] = value
				result.Truncated = true
			}
		}
	}
	for id, count := range counts {
		path := o.paths[id]
		if path == nil {
			path = &SankeyPath{ID: "other", Inbound: "other", RuleID: "other", RuleName: "Other / unretained details", EffectiveOutbound: "other", Target: "other", Other: true}
		}
		copy := *path
		if path.Other {
			result.Truncated = true
		}
		copy.Upload, copy.Download, copy.Connections, copy.Failures = count.Upload, count.Download, count.Connections, count.Failures
		value := float64(count.Upload) + float64(count.Download)
		if options.Metric == "upload" {
			value = float64(count.Upload)
		}
		if options.Metric == "download" {
			value = float64(count.Download)
		}
		if options.Metric != "cumulative" {
			value /= options.Window.Seconds()
		}
		copy.Value = value
		copy.Filter = query
		copy.Filter.Since, copy.Filter.Until = start, end
		copy.Filter.Anchor = result.Anchor
		copy.Filter.PathIDs = []string{id}
		if ids := pathFlowIDs[id]; len(ids) > 0 {
			sort.Strings(ids)
			copy.Filter.FlowIDs = ids
		}
		result.Paths = append(result.Paths, copy)
		result.Total += value
		addCounter(&result.Upload, count.Upload)
		addCounter(&result.Download, count.Download)
		addCounter(&result.Failures, count.Failures)
	}
	sortPaths(result.Paths)
	if len(result.Paths) > options.Limit {
		other := SankeyPath{ID: "other:top-n", Inbound: "other", RuleID: "other", RuleName: "Other paths", EffectiveOutbound: "other", Target: "other", Other: true, Filter: query}
		other.Filter.Since, other.Filter.Until, other.Filter.Anchor = start, end, result.Anchor
		for _, path := range result.Paths[options.Limit-1:] {
			other.Value += path.Value
			addCounter(&other.Upload, path.Upload)
			addCounter(&other.Download, path.Download)
			addCounter(&other.Connections, path.Connections)
			addCounter(&other.Failures, path.Failures)
			other.Filter.PathIDs = append(other.Filter.PathIDs, path.ID)
			other.Filter.FlowIDs = append(other.Filter.FlowIDs, path.Filter.FlowIDs...)
		}
		result.Paths = append(result.Paths[:options.Limit-1], other)
	}
	result.buildGraph()
	return result
}

func boolCounter(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

// WithoutExpiredDetails preserves measured weights while removing expired
// target/client/rule metadata from a frozen, disconnected helper snapshot.
func (result SankeySnapshot) WithoutExpiredDetails(before time.Time) (SankeySnapshot, bool) {
	kept := make([]SankeyPath, 0, len(result.Paths))
	other := SankeyPath{ID: "other:expired", Inbound: "other", RuleID: "other", RuleName: "Expired aggregate details", EffectiveOutbound: "other", Target: "other", Other: true}
	changed := false
	for _, path := range result.Paths {
		if path.Other || path.LastSeen.IsZero() || !path.LastSeen.Before(before) {
			kept = append(kept, path)
			continue
		}
		changed = true
		other.Value += path.Value
		addCounter(&other.Upload, path.Upload)
		addCounter(&other.Download, path.Download)
		addCounter(&other.Connections, path.Connections)
		addCounter(&other.Failures, path.Failures)
	}
	if !changed {
		return result, false
	}
	for index, path := range kept {
		if path.ID == other.ID {
			other.Value += path.Value
			addCounter(&other.Upload, path.Upload)
			addCounter(&other.Download, path.Download)
			addCounter(&other.Connections, path.Connections)
			addCounter(&other.Failures, path.Failures)
			kept = append(kept[:index], kept[index+1:]...)
			break
		}
	}
	result.Paths = append(kept, other)
	result.Nodes, result.Links = []SankeyNode{}, []SankeyLink{}
	result.Truncated, result.AnchorExpired = true, true
	result.buildGraph()
	return result, true
}

func (result *SankeySnapshot) buildGraph() {
	nodes := map[string]SankeyNode{}
	links := map[string]*SankeyLink{}
	for _, path := range result.Paths {
		labels := []string{path.Inbound, path.RuleName, path.EffectiveOutbound, path.Target}
		keys := []string{path.Inbound, path.RuleID, path.EffectiveOutbound, path.Target}
		kinds := []string{"inbound", "rule", "outbound", "destination"}
		ids := make([]string, 4)
		for index := range labels {
			if labels[index] == "" {
				labels[index] = "Unknown"
			}
			if keys[index] == "" {
				keys[index] = "unknown"
			}
			ids[index] = stableTrafficID(kinds[index]+":", keys[index])
			nodes[ids[index]] = SankeyNode{ID: ids[index], Label: labels[index], Kind: kinds[index], Column: index}
		}
		for index := 0; index < 3; index++ {
			id := ids[index] + "/" + ids[index+1]
			link := links[id]
			if link == nil {
				link = &SankeyLink{ID: stableTrafficID("link:", id), Source: ids[index], Target: ids[index+1], PathIDs: []string{}}
				links[id] = link
			}
			link.Value += path.Value
			link.PathIDs = append(link.PathIDs, path.ID)
		}
	}
	for _, node := range nodes {
		result.Nodes = append(result.Nodes, node)
	}
	for _, link := range links {
		result.Links = append(result.Links, *link)
	}
	sort.Slice(result.Nodes, func(i, j int) bool {
		if result.Nodes[i].Column != result.Nodes[j].Column {
			return result.Nodes[i].Column < result.Nodes[j].Column
		}
		return result.Nodes[i].ID < result.Nodes[j].ID
	})
	sort.Slice(result.Links, func(i, j int) bool { return result.Links[i].ID < result.Links[j].ID })
}

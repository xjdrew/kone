package kone

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	processinfo "github.com/xjdrew/kone/pkg/process"
)

const TrafficScope = "observed_kone_business_payload"

type ObservationOptions struct {
	Capacity     int
	PathCapacity int
	Retention    time.Duration
	Now          func() time.Time
}

type FlowRecord struct {
	ID                string     `json:"id"`
	SessionID         string     `json:"session_id"`
	ConfigVersion     uint64     `json:"config_version"`
	Inbound           string     `json:"inbound"`
	Protocol          string     `json:"protocol"`
	Source            string     `json:"source"`
	Destination       string     `json:"destination"`
	Target            string     `json:"target"`
	Domain            string     `json:"domain,omitempty"`
	DomainSource      string     `json:"domain_source"`
	FakeIP            string     `json:"fake_ip,omitempty"`
	RealDestination   string     `json:"real_destination,omitempty"`
	ProcessStatus     string     `json:"process_status"`
	ProcessReason     string     `json:"process_reason,omitempty"`
	ProcessPID        uint32     `json:"process_pid,omitempty"`
	ProcessName       string     `json:"process_name,omitempty"`
	ProcessPath       string     `json:"process_path,omitempty"`
	ProcessSource     string     `json:"process_source,omitempty"`
	ProcessObservedAt *time.Time `json:"process_observed_at,omitempty"`
	ProcessStartedAt  *time.Time `json:"process_started_at,omitempty"`
	GeoIPVersion      string     `json:"geoip_version,omitempty"`
	GeoIPSHA256       string     `json:"geoip_sha256,omitempty"`
	RuleID            string     `json:"rule_id"`
	RuleName          string     `json:"rule_name"`
	RuleSource        string     `json:"rule_source"`
	RuleOrder         int        `json:"rule_order"`
	ExpectedOutbound  string     `json:"expected_outbound"`
	EffectiveOutbound string     `json:"effective_outbound"`
	AttemptedOutbound string     `json:"attempted_outbound"`
	Fallback          bool       `json:"fallback"`
	Protected         bool       `json:"protected"`
	Stage             string     `json:"stage"`
	Status            string     `json:"status"`
	Error             string     `json:"error,omitempty"`
	ErrorKind         string     `json:"error_kind,omitempty"`
	StartedAt         time.Time  `json:"started_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	EndedAt           *time.Time `json:"ended_at,omitempty"`
	Upload            uint64     `json:"upload"`
	Download          uint64     `json:"download"`
	UploadPackets     uint64     `json:"upload_packets"`
	DownloadPackets   uint64     `json:"download_packets"`
	sequence          uint64
	pathID            string
}

type TrafficTotals struct {
	Started         uint64  `json:"started"`
	Active          uint64  `json:"active"`
	Closed          uint64  `json:"closed"`
	Failed          uint64  `json:"failed"`
	Rejected        uint64  `json:"rejected"`
	Canceled        uint64  `json:"canceled"`
	Upload          uint64  `json:"upload"`
	Download        uint64  `json:"download"`
	UploadPackets   uint64  `json:"upload_packets"`
	DownloadPackets uint64  `json:"download_packets"`
	Bytes           uint64  `json:"bytes"`
	UploadRate      float64 `json:"upload_rate"`
	DownloadRate    float64 `json:"download_rate"`
}

type TrafficQuery struct {
	Protocol string    `json:"protocol,omitempty"`
	Status   string    `json:"status,omitempty"`
	Outbound string    `json:"outbound,omitempty"`
	RuleID   string    `json:"rule_id,omitempty"`
	Inbound  string    `json:"inbound,omitempty"`
	Target   string    `json:"target,omitempty"`
	Source   string    `json:"source,omitempty"`
	Cursor   string    `json:"cursor,omitempty"`
	Anchor   string    `json:"anchor,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	Until    time.Time `json:"until,omitempty"`
	Limit    int       `json:"limit,omitempty"`
	PathIDs  []string  `json:"path_ids,omitempty"`
	FlowIDs  []string  `json:"flow_ids,omitempty"`
}

type TrafficSnapshot struct {
	Frozen           bool          `json:"frozen"`
	SessionID        string        `json:"session_id"`
	StartedAt        time.Time     `json:"started_at"`
	Timestamp        time.Time     `json:"timestamp"`
	Scope            string        `json:"scope"`
	Totals           TrafficTotals `json:"totals"`
	Records          []FlowRecord  `json:"records"`
	Total            int           `json:"total"`
	NextCursor       string        `json:"next_cursor,omitempty"`
	Anchor           string        `json:"anchor"`
	Capacity         int           `json:"capacity"`
	RetentionSeconds int64         `json:"retention_seconds"`
	DroppedDetails   uint64        `json:"dropped_details"`
	Recording        bool          `json:"recording"`
	Truncated        bool          `json:"truncated"`
	AnchorExpired    bool          `json:"anchor_expired"`
}

type pathCounts struct {
	Upload      uint64
	Download    uint64
	Connections uint64
	Failures    uint64
}

type trafficBucket struct {
	second    int64
	counts    pathCounts
	paths     map[string]pathCounts
	flows     map[string]pathCounts
	truncated bool
}

type TrafficObserver struct {
	mu           sync.Mutex
	now          func() time.Time
	session      string
	started      time.Time
	capacity     int
	pathCapacity int
	retention    time.Duration
	recording    bool
	sequence     uint64
	records      map[string]*FlowRecord
	order        []string
	totals       TrafficTotals
	dropped      uint64
	paths        map[string]*SankeyPath
	buckets      [61]trafficBucket
}

type ObservedFlow struct {
	observer       *TrafficObserver
	id             string
	done           atomic.Bool
	pathID         string
	stage          string
	transferFailed bool
}

func randomSessionID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	return fmt.Sprint("session-", time.Now().UnixNano())
}

func NewTrafficObserver(options ObservationOptions) *TrafficObserver {
	if options.Capacity <= 0 {
		options.Capacity = 4096
	}
	if options.Capacity > 100000 {
		options.Capacity = 100000
	}
	if options.PathCapacity <= 0 {
		options.PathCapacity = 512
	}
	if options.PathCapacity > 4096 {
		options.PathCapacity = 4096
	}
	if options.Retention <= 0 {
		options.Retention = 30 * time.Minute
	}
	if options.Retention > 24*time.Hour {
		options.Retention = 24 * time.Hour
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &TrafficObserver{now: options.Now, session: randomSessionID(), started: options.Now(), capacity: options.Capacity, pathCapacity: options.PathCapacity, retention: options.Retention, recording: true, records: map[string]*FlowRecord{}, paths: map[string]*SankeyPath{}}
}

func (one *One) SetTrafficObserver(observer *TrafficObserver) error {
	if observer == nil {
		return errors.New("traffic observer is nil")
	}
	one.mu.Lock()
	defer one.mu.Unlock()
	if one.started || one.closed {
		return errors.New("traffic observer must be set before Run")
	}
	one.flows.observer.Store(observer)
	return nil
}

func (one *One) TrafficObserver() *TrafficObserver {
	if observer := one.flows.observer.Load(); observer != nil {
		return observer
	}
	observer := NewTrafficObserver(ObservationOptions{})
	if one.flows.observer.CompareAndSwap(nil, observer) {
		return observer
	}
	return one.flows.observer.Load()
}

func (one *One) TrafficSnapshot(query TrafficQuery) TrafficSnapshot {
	return one.TrafficObserver().Snapshot(query)
}

func addCounter(destination *uint64, value uint64) {
	if math.MaxUint64-*destination < value {
		*destination = math.MaxUint64
	} else {
		*destination += value
	}
}

func (o *TrafficObserver) Begin(record FlowRecord) *ObservedFlow {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sequence++
	id := fmt.Sprintf("%s-%020d", o.session, o.sequence)
	addCounter(&o.totals.Started, 1)
	addCounter(&o.totals.Active, 1)
	if o.recording {
		now := o.now()
		o.prune(now)
		if len(o.records) >= o.capacity {
			index := 0
			for i, old := range o.order {
				if value := o.records[old]; value != nil && value.EndedAt != nil {
					index = i
					break
				}
			}
			delete(o.records, o.order[index])
			o.order = append(o.order[:index], o.order[index+1:]...)
			o.dropped++
		}
		record.ID, record.SessionID, record.sequence = id, o.session, o.sequence
		record.StartedAt, record.UpdatedAt = now, now
		record.Status, record.Stage = "connecting", "routing"
		if record.Inbound == "" {
			record.Inbound = "tun"
		}
		if record.DomainSource == "" {
			record.DomainSource = "unknown"
		}
		if record.ProcessStatus == "" {
			record.ProcessStatus, record.ProcessReason = "unknown", "process ownership unavailable"
		}
		if record.Target == "" {
			record.Target = record.Destination
		}
		o.records[id] = &record
		o.order = append(o.order, id)
	}
	return &ObservedFlow{observer: o, id: id, stage: "routing"}
}

func (f *ObservedFlow) ID() string { return f.id }

func (f *ObservedFlow) Stage(stage string) {
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	f.stage = stage
	if record := o.records[f.id]; record != nil && record.EndedAt == nil {
		record.Stage, record.UpdatedAt = stage, o.now()
	}
}

func (f *ObservedFlow) Decision(decision RoutingDecision, effective, realDestination string, connected bool) {
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	if record := o.records[f.id]; record != nil && record.EndedAt == nil {
		record.RuleID, record.RuleName, record.RuleSource, record.RuleOrder = decision.RuleID, decision.RuleName, decision.RuleSource, decision.RuleOrder
		record.GeoIPVersion, record.GeoIPSHA256 = decision.GeoIPVersion, decision.GeoIPSHA256
		record.ExpectedOutbound, record.AttemptedOutbound = decision.Outbound, effective
		record.Protected = decision.Protected
		record.Fallback = effective != "" && effective != decision.Outbound
		if connected {
			record.EffectiveOutbound, record.Status = effective, "active"
		}
		record.RealDestination, record.UpdatedAt = realDestination, o.now()
	}
}

func (f *ObservedFlow) Process(result processinfo.Result) {
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	if record := o.records[f.id]; record != nil {
		record.ProcessStatus, record.ProcessReason, record.ProcessSource = result.Status, result.Reason, result.Source
		record.ProcessPID, record.ProcessName, record.ProcessPath = result.PID, result.Name, result.Path
		observed := result.ObservedAt
		record.ProcessObservedAt = &observed
		if !result.StartedAt.IsZero() {
			started := result.StartedAt
			record.ProcessStartedAt = &started
		}
	}
}

func (f *ObservedFlow) UpdateTarget(domain, fakeIP, target string) {
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	if record := o.records[f.id]; record != nil && record.EndedAt == nil {
		record.Domain, record.FakeIP, record.Target = domain, fakeIP, target
		if domain != "" {
			record.DomainSource = "fake-ip"
		}
	}
}

func (f *ObservedFlow) AddUpload(bytes, packets uint64)   { f.add(bytes, 0, packets, 0) }
func (f *ObservedFlow) AddDownload(bytes, packets uint64) { f.add(0, bytes, 0, packets) }

func (f *ObservedFlow) add(upload, download, uploadPackets, downloadPackets uint64) {
	if f.done.Load() {
		return
	}
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	if f.done.Load() {
		return
	}
	addCounter(&o.totals.Upload, upload)
	addCounter(&o.totals.Download, download)
	addCounter(&o.totals.UploadPackets, uploadPackets)
	addCounter(&o.totals.DownloadPackets, downloadPackets)
	pathID := f.pathID
	if record := o.records[f.id]; record != nil {
		addCounter(&record.Upload, upload)
		addCounter(&record.Download, download)
		addCounter(&record.UploadPackets, uploadPackets)
		addCounter(&record.DownloadPackets, downloadPackets)
		record.UpdatedAt = o.now()
		pathID = o.path(record)
	}
	if pathID == "" {
		pathID = "other"
		o.countPath(f.id, pathID, 0, 0, 1, 0)
	}
	f.pathID = pathID
	o.countPath(f.id, pathID, upload, download, 0, 0)
}

func (f *ObservedFlow) TransferError(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return
	}
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	f.transferFailed = true
	if record := o.records[f.id]; record != nil && record.Error == "" {
		record.Error, record.ErrorKind = safeTrafficError(err), "transfer"
	}
}

func (f *ObservedFlow) Finish(err error, stopping bool) {
	if !f.done.CompareAndSwap(false, true) {
		return
	}
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.totals.Active > 0 {
		o.totals.Active--
	}
	status, kind := "closed", ""
	if stopping || errors.Is(err, context.Canceled) {
		status, kind = "canceled", "canceled"
	} else if errors.Is(err, ErrRejected) {
		status, kind = "rejected", "policy"
	} else if errors.Is(err, ErrUDPUnsupported) {
		status, kind = "rejected", "unsupported"
	} else if err != nil && !errors.Is(err, net.ErrClosed) {
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() && f.stage == "transfer" {
			kind = "idle_timeout"
		} else {
			status, kind = "failed", "connection"
		}
	}
	if err == nil && f.transferFailed && !stopping {
		status, kind = "failed", "transfer"
	}
	typedStage := ""
	if status == "failed" && err != nil {
		typedStage = DiagnosticStage(err)
		if typedStage != "" {
			kind = typedStage
		}
	}
	pathID := f.pathID
	if record := o.records[f.id]; record != nil {
		if err == nil && record.Error != "" && !stopping {
			status, kind = "failed", record.ErrorKind
		}
		if err != nil && kind != "canceled" {
			record.Error = safeTrafficError(err)
		}
		if kind != "" {
			record.ErrorKind = kind
		}
		now := o.now()
		record.EndedAt = &now
		record.UpdatedAt = now
		record.Status = status
		if typedStage != "" {
			record.Stage = typedStage
		}
		if record.Stage == "transfer" || status == "closed" || status == "canceled" {
			record.Stage = "closed"
		}
		pathID = o.path(record)
	}
	failures := uint64(0)
	switch status {
	case "failed":
		addCounter(&o.totals.Failed, 1)
		failures = 1
	case "rejected":
		addCounter(&o.totals.Rejected, 1)
		failures = 1
	case "canceled":
		addCounter(&o.totals.Canceled, 1)
	default:
		addCounter(&o.totals.Closed, 1)
	}
	connections := uint64(0)
	if pathID == "" {
		pathID = "other"
		connections = 1
	}
	o.countPath(f.id, pathID, 0, 0, connections, failures)
}

var credentialPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+(?::[^\s/@]*)?@`)

func safeTrafficError(err error) string {
	message := credentialPattern.ReplaceAllString(err.Error(), "${1}[redacted]@")
	message = strings.Map(func(r rune) rune {
		if r < ' ' || r == 127 {
			return ' '
		}
		return r
	}, message)
	if len(message) > 512 {
		message = message[:512] + "…"
	}
	return message
}

func (o *TrafficObserver) SetRecording(enabled bool) {
	o.mu.Lock()
	o.recording = enabled
	o.mu.Unlock()
}

// Clear removes sensitive detail and graph history while lifetime counters
// remain explicit. Existing flows continue accounting into the Other bucket.
func (o *TrafficObserver) Clear() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dropped += uint64(len(o.records))
	o.records = map[string]*FlowRecord{}
	o.order = nil
	o.paths = map[string]*SankeyPath{"other": {ID: "other", Inbound: "other", RuleID: "other", RuleName: "Cleared history", EffectiveOutbound: "other", Target: "other", Other: true, Upload: o.totals.Upload, Download: o.totals.Download, Connections: o.totals.Started, Failures: o.totals.Failed + o.totals.Rejected}}
	o.buckets = [61]trafficBucket{}
}

func (o *TrafficObserver) prune(now time.Time) {
	kept := o.order[:0]
	for _, id := range o.order {
		record := o.records[id]
		if record != nil && record.EndedAt != nil && now.Sub(*record.EndedAt) > o.retention {
			delete(o.records, id)
		} else if record != nil {
			kept = append(kept, id)
		}
	}
	o.order = kept
}

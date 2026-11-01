package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/rpc"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

type Connector func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error)
type RemoteEngine struct {
	mu                               sync.Mutex
	config                           []byte
	version                          uint64
	connect                          Connector
	client                           *rpc.Client
	commands, events                 io.ReadWriteCloser
	ready, done, closeDone           chan struct{}
	started, closed                  bool
	readyOnce, finishOnce, closeOnce sync.Once
	runError, closeError             error
	cancel                           context.CancelFunc
	recorder                         func(string, int) error
	identity                         DeviceIdentity
	archive                          *StopReply
	archiveAnonymous                 bool
	geoIP                            *geoip.Database
	requests                         chan struct{}
	probeSequence                    atomic.Uint64
	logs, logSink                    *logstore.Store
	logCursor                        uint64
	logStatus                        logstore.RemoteStatus
}

func NewRemote(cfg *kone.KoneConfig, connect Connector) (*RemoteEngine, error) {
	if cfg == nil {
		return nil, errors.New("configuration is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if connect == nil {
		return nil, errors.New("privileged helper transport is unavailable")
	}
	return &RemoteEngine{config: data, version: 1, connect: connect, ready: make(chan struct{}), done: make(chan struct{}), closeDone: make(chan struct{}), requests: make(chan struct{}, 8), logs: logstore.New()}, nil
}
func (e *RemoteEngine) Ready() <-chan struct{} { return e.ready }
func (e *RemoteEngine) SetTrafficObserver(observer *kone.TrafficObserver) error {
	if observer == nil {
		return errors.New("traffic observer is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started || e.closed {
		return errors.New("observer must be set before Run")
	}
	return nil
}
func (e *RemoteEngine) SetConfigVersion(version uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if version == 0 || e.started || e.closed {
		return errors.New("initial version must be positive and set before Run")
	}
	e.version = version
	return nil
}
func (e *RemoteEngine) SetCaptureRecorder(record func(string, int) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if record == nil || e.started || e.closed {
		return errors.New("capture recorder must be set before Run")
	}
	e.recorder = record
	return nil
}
func (e *RemoteEngine) CaptureDeviceIdentity() (string, int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.identity.Name, e.identity.Index, e.identity.Known
}
func (e *RemoteEngine) finish(err error) {
	e.finishOnce.Do(func() {
		e.mu.Lock()
		e.runError = err
		e.logStatus.Connected = false
		if err != nil {
			e.logStatus.Error = logstore.RedactText(err.Error())
		}
		sink, local := e.logSink, e.logs
		e.mu.Unlock()
		if err != nil {
			record := logstore.Record{Level: "ERROR", Source: "helper", Message: "Network helper stopped", Attrs: map[string]any{"error": err.Error()}}
			local.Append(record)
			if sink != nil && sink != local {
				sink.Append(record)
			}
		}
		close(e.done)
	})
}

type callbacks struct{ engine *RemoteEngine }

func (c *callbacks) Device(identity DeviceIdentity, _ *Empty) error {
	if !identity.Known || identity.Name == "" || identity.Index <= 0 {
		return errors.New("helper supplied an invalid device identity")
	}
	e := c.engine
	e.mu.Lock()
	record := e.recorder
	e.mu.Unlock()
	if record == nil {
		return errors.New("no durable capture recorder was installed")
	}
	if err := record(identity.Name, identity.Index); err != nil {
		return errors.New("durable capture recording failed")
	}
	e.mu.Lock()
	e.identity = identity
	e.mu.Unlock()
	return nil
}
func (c *callbacks) Finished(event FinishedEvent, _ *Empty) error {
	var err error
	if event.Error != "" {
		err = errors.New(event.Error)
	}
	if event.LogsDegraded {
		c.engine.mu.Lock()
		c.engine.logStatus.Error = "Some helper logs were not acknowledged before shutdown"
		c.engine.mu.Unlock()
	}
	c.engine.finish(err)
	return nil
}

func (e *RemoteEngine) Run(parent context.Context) error {
	e.mu.Lock()
	if e.started || e.closed {
		e.mu.Unlock()
		return errors.New("remote engine can only run once")
	}
	e.started = true
	ctx, cancel := context.WithCancel(parent)
	e.cancel = cancel
	config, version, database := e.config, e.version, e.geoIP
	e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		e.finish(err)
		return err
	}
	commands, events, err := e.connect(ctx)
	if err != nil {
		e.finish(err)
		return err
	}
	if commands == nil || events == nil {
		if commands != nil {
			commands.Close()
		}
		if events != nil {
			events.Close()
		}
		err = errors.New("privileged helper transport is incomplete")
		e.finish(err)
		return err
	}
	disconnect := func() {
		e.mu.Lock()
		closed := e.closed
		e.mu.Unlock()
		if !closed {
			e.finish(errors.New("privileged network helper disconnected; cleanup result is unknown"))
		}
	}
	client := rpc.NewClient(disconnectStream{ReadWriteCloser: commands, disconnected: disconnect})
	server := rpc.NewServer()
	if err = server.RegisterName("Callbacks", &callbacks{engine: e}); err != nil {
		client.Close()
		events.Close()
		e.finish(err)
		return err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		client.Close()
		events.Close()
		e.finish(context.Canceled)
		return context.Canceled
	}
	e.client, e.commands, e.events = client, commands, events
	e.logStatus.Connected = true
	e.mu.Unlock()
	go server.ServeConn(disconnectStream{ReadWriteCloser: events, disconnected: disconnect})
	var reply Empty
	request := StartRequest{TOML: config, Version: version}
	if database != nil {
		request.GeoIP = database.Bytes()
		request.GeoIPSHA256 = database.Metadata().SHA256
		request.GeoIPBuiltin = database.Metadata().Builtin
	}
	call := client.Go("Network.Start", request, &reply, make(chan *rpc.Call, 1))
	select {
	case result := <-call.Done:
		if result.Error != nil {
			e.finish(result.Error)
		} else {
			e.readyOnce.Do(func() { close(e.ready) })
		}
	case <-ctx.Done():
		e.Close()
		e.finish(ctx.Err())
	}
	select {
	case <-e.done:
	case <-ctx.Done():
		e.Close()
		e.finish(ctx.Err())
	}
	e.mu.Lock()
	err = e.runError
	e.mu.Unlock()
	return err
}

func (e *RemoteEngine) call(method string, request, reply any, timeout time.Duration) error {
	select {
	case e.requests <- struct{}{}:
		defer func() { <-e.requests }()
	default:
		return errors.New("network helper request capacity is busy")
	}
	e.mu.Lock()
	client := e.client
	closed := e.closed
	e.mu.Unlock()
	if client == nil || closed {
		return errors.New("network helper is not connected")
	}
	call := client.Go("Network."+method, request, reply, make(chan *rpc.Call, 1))
	select {
	case result := <-call.Done:
		return result.Error
	case <-time.After(timeout):
		client.Close()
		e.finish(errors.New("network helper timed out; capture cleanup must be checked"))
		return errors.New("network helper request timed out")
	}
}

func (e *RemoteEngine) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		client, cancel := e.client, e.cancel
		events := e.events
		e.mu.Unlock()
		var final StopReply
		var err error
		if client != nil {
			call := client.Go("Network.Stop", Empty{}, &final, make(chan *rpc.Call, 1))
			select {
			case result := <-call.Done:
				err = result.Error
			case <-time.After(20 * time.Second):
				err = errors.New("privileged helper cleanup timed out; recovery is required")
			}
		}
		e.mu.Lock()
		e.closed = true
		e.closeError = err
		if final.LogsDegraded {
			e.logStatus.Error = "Some helper logs were not acknowledged before shutdown"
		}
		if client != nil && err == nil {
			e.archive = &final
			e.identity = final.Identity
		}
		e.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if client != nil {
			client.Close()
		}
		if events != nil {
			events.Close()
		}
		e.finish(err)
		close(e.closeDone)
	})
	<-e.closeDone
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closeError
}

func (e *RemoteEngine) Reload(cfg *kone.KoneConfig) error {
	e.mu.Lock()
	version := e.version + 1
	e.mu.Unlock()
	return e.ReloadVersion(cfg, version)
}
func (e *RemoteEngine) ReloadVersion(cfg *kone.KoneConfig, version uint64) error {
	if cfg == nil || version == 0 {
		return errors.New("invalid configuration revision")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	var reply Empty
	if err = e.call("Reload", StartRequest{TOML: data, Version: version}, &reply, 10*time.Second); err != nil {
		return err
	}
	e.mu.Lock()
	e.config, e.version = data, version
	e.mu.Unlock()
	return nil
}

func simpleArchiveQuery(query kone.TrafficQuery) bool {
	return query.Protocol == "" && query.Status == "" && query.Outbound == "" && query.RuleID == "" && query.Inbound == "" && query.Target == "" && query.Source == "" && query.Cursor == "" && query.Anchor == "" && len(query.PathIDs) == 0 && len(query.FlowIDs) == 0 && query.Since.IsZero() && query.Until.IsZero()
}
func (e *RemoteEngine) TrafficData(query kone.TrafficQuery, options kone.SankeyOptions) (kone.TrafficSnapshot, kone.SankeySnapshot, error) {
	archive, closed := e.cachedArchive()
	if closed {
		if archive == nil || !simpleArchiveQuery(query) || options.Window > time.Second || options.Metric != "" && options.Metric != "total" && options.Metric != "cumulative" {
			return kone.TrafficSnapshot{}, kone.SankeySnapshot{}, errors.New("capture is stopped; this filtered or live snapshot is unavailable")
		}
		traffic, graph := archive.Traffic.Traffic, archive.Traffic.Sankey
		traffic.Records = cloneDesktopValue(traffic.Records)
		traffic.NextCursor = ""
		if query.Limit > 0 && query.Limit < len(traffic.Records) {
			traffic.Records = traffic.Records[:query.Limit]
			traffic.Truncated = true
		}
		traffic.Frozen = true
		graph.Frozen = true
		if options.Metric == "cumulative" {
			graph = archive.Cumulative
			graph.Frozen = true
		}
		return traffic, cloneDesktopValue(graph), nil
	}
	var reply TrafficReply
	err := e.call("Traffic", TrafficRequest{Query: query, Options: options}, &reply, 3*time.Second)
	return reply.Traffic, reply.Sankey, err
}
func (e *RemoteEngine) FlowRecord(id string) (kone.FlowRecord, bool, error) {
	archive, closed := e.cachedArchive()
	if closed {
		if archive != nil {
			for _, record := range archive.Traffic.Traffic.Records {
				if record.ID == id {
					return cloneDesktopValue(record), true, nil
				}
			}
		}
		return kone.FlowRecord{}, false, nil
	}
	var reply FlowReply
	err := e.call("Flow", id, &reply, 3*time.Second)
	return reply.Record, reply.Found, err
}
func (e *RemoteEngine) DNSData() (kone.DNSRuntimeStatus, []kone.DNSQueryEvent, error) {
	archive, closed := e.cachedArchive()
	if closed {
		if archive == nil {
			return kone.DNSRuntimeStatus{}, nil, errors.New("final DNS observations are unavailable")
		}
		return cloneDesktopValue(archive.DNS.Status), cloneDesktopValue(archive.DNS.Queries), nil
	}
	var reply DNSReply
	err := e.call("DNS", Empty{}, &reply, 3*time.Second)
	return reply.Status, reply.Queries, err
}
func (e *RemoteEngine) ClearObservation() error {
	e.mu.Lock()
	if e.closed {
		if e.archive != nil {
			e.archive = anonymousArchive(e.archive, true)
			e.archiveAnonymous = true
		}
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()
	var reply Empty
	return e.call("Clear", Empty{}, &reply, 3*time.Second)
}

func cloneDesktopValue[T any](value T) T {
	data, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(data, &result)
	return result
}
func (e *RemoteEngine) SetGeoIPDatabase(database *geoip.Database) error {
	if database == nil || len(database.Metadata().SHA256) != 64 {
		return errors.New("invalid GeoIP database")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started || e.closed {
		return errors.New("initial GeoIP database must be set before Run")
	}
	e.geoIP = database
	return nil
}
func (e *RemoteEngine) ApplyGeoIPDatabase(database *geoip.Database, version uint64) error {
	if database == nil {
		return errors.New("GeoIP database is nil")
	}
	var reply Empty
	err := e.call("GeoIP", GeoIPRequest{Data: database.Bytes(), SHA256: database.Metadata().SHA256, Builtin: database.Metadata().Builtin, BaseVersion: version}, &reply, 10*time.Second)
	if err == nil {
		e.mu.Lock()
		e.geoIP = database
		e.mu.Unlock()
	}
	return err
}
func (e *RemoteEngine) GeoIPData() (kone.GeoIPRuntimeStatus, error) {
	var reply kone.GeoIPRuntimeStatus
	err := e.call("GeoIPStatus", Empty{}, &reply, 3*time.Second)
	return reply, err
}
func (e *RemoteEngine) RollbackGeoIP(version uint64) error {
	var reply Empty
	return e.call("GeoIPRollback", version, &reply, 10*time.Second)
}

func (e *RemoteEngine) ProbeDiagnostic(ctx context.Context, outbound, target string, withTLS bool) (kone.DiagnosticResult, error) {
	return e.ProbeDiagnosticVersion(ctx, outbound, target, withTLS, 0)
}
func (e *RemoteEngine) ProbeDiagnosticVersion(ctx context.Context, outbound, target string, withTLS bool, expectedVersion uint64) (kone.DiagnosticResult, error) {
	var reply kone.DiagnosticResult
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	select {
	case e.requests <- struct{}{}:
		defer func() { <-e.requests }()
	default:
		return reply, errors.New("network helper diagnostic capacity is busy")
	}
	e.mu.Lock()
	client, closed := e.client, e.closed
	e.mu.Unlock()
	if client == nil || closed {
		return reply, errors.New("network helper is not connected")
	}
	id := strconv.FormatUint(e.probeSequence.Add(1), 10)
	budget := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < budget {
		budget = time.Until(deadline)
	}
	call := client.Go("Network.Probe", ProbeRequest{ID: id, Outbound: outbound, Target: target, TLS: withTLS, TimeoutMS: budget.Milliseconds(), ExpectedVersion: expectedVersion, Deadline: time.Now().Add(budget)}, &reply, make(chan *rpc.Call, 1))
	select {
	case result := <-call.Done:
		if err := ctx.Err(); err != nil {
			return kone.DiagnosticResult{}, err
		}
		return reply, result.Error
	case <-ctx.Done():
		var ignored Empty
		client.Go("Network.CancelProbe", id, &ignored, make(chan *rpc.Call, 1))
		return kone.DiagnosticResult{}, ctx.Err()
	case <-time.After(7 * time.Second):
		var ignored Empty
		client.Go("Network.CancelProbe", id, &ignored, make(chan *rpc.Call, 1))
		return kone.DiagnosticResult{}, errors.New("network helper diagnostic timed out")
	}
}

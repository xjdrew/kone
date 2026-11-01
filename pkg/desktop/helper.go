// Package desktop separates ordinary local management from the privileged
// network engine. Helpers accept no configuration or credentials in arguments.
package desktop

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/rpc"
	"regexp"
	"sync"
	"time"

	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
)

type NetworkEngine interface {
	Run(context.Context) error
	Close() error
	Ready() <-chan struct{}
	SetConfigVersion(uint64) error
	ReloadVersion(*kone.KoneConfig, uint64) error
	SetCaptureRecorder(func(string, int) error) error
	CaptureDeviceIdentity() (string, int, bool)
	TrafficData(kone.TrafficQuery, kone.SankeyOptions) (kone.TrafficSnapshot, kone.SankeySnapshot, error)
	FlowRecord(string) (kone.FlowRecord, bool, error)
	DNSData() (kone.DNSRuntimeStatus, []kone.DNSQueryEvent, error)
	ClearObservation() error
}
type EngineFactory func(*kone.KoneConfig) (NetworkEngine, error)
type Empty struct{}
type StartRequest struct {
	TOML          []byte
	Version       uint64
	GeoIP         []byte
	GeoIPSHA256   string
	GeoIPBuiltin  bool
	GeoIPFormat   string
	GeoIPProvider string
}
type GeoIPRequest struct {
	Data        []byte
	SHA256      string
	Builtin     bool
	Format      string
	Provider    string
	BaseVersion uint64
}
type ProbeRequest struct {
	ID               string
	Outbound, Target string
	TLS              bool
	Options          kone.DiagnosticOptions
	TimeoutMS        int64
	ExpectedVersion  uint64
	Deadline         time.Time
	ReportProgress   bool
}
type DeviceIdentity struct {
	Name  string
	Index int
	Known bool
}
type FinishedEvent struct {
	Error        string
	LogsDegraded bool
}
type TrafficRequest struct {
	Query   kone.TrafficQuery
	Options kone.SankeyOptions
}
type TrafficReply struct {
	Traffic kone.TrafficSnapshot
	Sankey  kone.SankeySnapshot
}
type FlowReply struct {
	Record kone.FlowRecord
	Found  bool
}
type DNSReply struct {
	Status  kone.DNSRuntimeStatus
	Queries []kone.DNSQueryEvent
}
type StopReply struct {
	Traffic      TrafficReply
	Cumulative   kone.SankeySnapshot
	DNS          DNSReply
	Identity     DeviceIdentity
	LogsDegraded bool
}

type disconnectStream struct {
	io.ReadWriteCloser
	disconnected func()
}

func (s disconnectStream) Read(data []byte) (int, error) {
	n, err := s.ReadWriteCloser.Read(data)
	if err != nil {
		s.disconnected()
	}
	return n, err
}
func (s disconnectStream) Write(data []byte) (int, error) {
	n, err := s.ReadWriteCloser.Write(data)
	if err != nil {
		s.disconnected()
	}
	return n, err
}

var credentialURL = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+(?::[^\s/@]*)?@`)

func helperError(err error) string {
	if err == nil {
		return ""
	}
	message := credentialURL.ReplaceAllString(err.Error(), "${1}[redacted]@")
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}

type helperService struct {
	mu                 sync.Mutex
	ctx                context.Context
	engine             NetworkEngine
	factory            EngineFactory
	events             *rpc.Client
	started            bool
	runCancel          context.CancelFunc
	runDone            chan struct{}
	runError           error
	probes             map[string]context.CancelFunc
	probeProgressSlots chan struct{}
	canceledProbes     map[string]time.Time
	logForwarder       *helperLogForwarder
	configureLogs      func(kone.GeneralConfig) error
	recoverDNS         func(context.Context, string) error
}

func (s *helperService) Start(request StartRequest, _ *Empty) (result error) {
	defer func() { s.logFailure("Capture startup failed", result) }()
	s.logEvent(slog.LevelInfo, "Network helper received capture request", slog.String("stage", "configuration"), slog.Uint64("config_version", request.Version))
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("network helper accepts one capture run")
	}
	s.started = true
	runCtx, cancel := context.WithCancel(s.ctx)
	s.runCancel = cancel
	s.mu.Unlock()
	if len(request.TOML) > 1024*1024 {
		return errors.New("helper configuration exceeds bound")
	}
	cfg, err := kone.ParseManagedConfig(request.TOML)
	if err != nil {
		return errors.New(helperError(err))
	}
	if s.configureLogs != nil {
		if err = s.configureLogs(cfg.General); err != nil {
			return err
		}
	}
	s.logEvent(slog.LevelInfo, "Network helper configuration validated", slog.String("stage", "configuration"), slog.Uint64("config_version", request.Version))
	engine, err := s.factory(cfg)
	if err != nil {
		return errors.New(helperError(err))
	}
	if err = engine.SetConfigVersion(request.Version); err != nil {
		engine.Close()
		return err
	}
	if len(request.GeoIP) > 0 || request.GeoIPBuiltin {
		if err = applyHelperGeoIP(engine, GeoIPRequest{Data: request.GeoIP, SHA256: request.GeoIPSHA256, Builtin: request.GeoIPBuiltin, Format: request.GeoIPFormat, Provider: request.GeoIPProvider}); err != nil {
			engine.Close()
			return err
		}
	}
	err = engine.SetCaptureRecorder(func(name string, index int) error {
		var reply Empty
		call := s.events.Go("Callbacks.Device", DeviceIdentity{Name: name, Index: index, Known: true}, &reply, make(chan *rpc.Call, 1))
		select {
		case result := <-call.Done:
			return result.Error
		case <-runCtx.Done():
			return runCtx.Err()
		case <-time.After(5 * time.Second):
			return errors.New("parent did not durably acknowledge created device")
		}
	})
	if err != nil {
		engine.Close()
		return err
	}
	s.mu.Lock()
	s.engine = engine
	s.runDone = make(chan struct{})
	done := s.runDone
	s.mu.Unlock()
	s.logEvent(slog.LevelInfo, "Network helper starting capture engine", slog.String("stage", "engine"), slog.Uint64("config_version", request.Version))
	go func() {
		err := engine.Run(runCtx)
		err = errors.Join(err, engine.Close())
		s.mu.Lock()
		s.runError = err
		s.mu.Unlock()
		close(done)
		if err == nil {
			s.logEvent(slog.LevelInfo, "Network helper engine cleanup completed", slog.String("stage", "cleanup"))
		}
		s.logFailure("Capture engine stopped", err)
		var reply Empty
		s.events.Call("Callbacks.Finished", FinishedEvent{Error: helperError(err), LogsDegraded: s.logsDegraded()}, &reply)
	}()
	select {
	case <-engine.Ready():
		s.logEvent(slog.LevelInfo, "Network helper capture is ready", slog.String("stage", "ready"), slog.Uint64("config_version", request.Version))
		return nil
	case <-done:
		s.mu.Lock()
		err := s.runError
		s.mu.Unlock()
		if err == nil {
			err = errors.New("helper engine stopped before readiness")
		}
		return errors.New(helperError(err))
	case <-runCtx.Done():
		engine.Close()
		return runCtx.Err()
	}
}

func (s *helperService) current() (NetworkEngine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return nil, errors.New("network helper has no engine")
	}
	return s.engine, nil
}
func (s *helperService) Reload(request StartRequest, _ *Empty) error {
	defer s.flushLogs()
	if len(request.TOML) > 1024*1024 {
		return errors.New("helper configuration exceeds bound")
	}
	cfg, err := kone.ParseManagedConfig(request.TOML)
	if err != nil {
		return errors.New(helperError(err))
	}
	engine, err := s.current()
	if err != nil {
		return err
	}
	if err = engine.ReloadVersion(cfg, request.Version); err != nil {
		return errors.New(helperError(err))
	}
	if s.configureLogs != nil {
		return s.configureLogs(cfg.General)
	}
	return nil
}
func (s *helperService) Traffic(request TrafficRequest, reply *TrafficReply) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	reply.Traffic, reply.Sankey, err = engine.TrafficData(request.Query, request.Options)
	return err
}
func (s *helperService) Flow(id string, reply *FlowReply) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	reply.Record, reply.Found, err = engine.FlowRecord(id)
	return err
}
func (s *helperService) DNS(_ Empty, reply *DNSReply) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	reply.Status, reply.Queries, err = engine.DNSData()
	return err
}
func (s *helperService) Clear(_ Empty, _ *Empty) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	return engine.ClearObservation()
}
func (s *helperService) Identity(_ Empty, reply *DeviceIdentity) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	reply.Name, reply.Index, reply.Known = engine.CaptureDeviceIdentity()
	return nil
}

type geoIPOwner interface {
	GeoIPStatus() kone.GeoIPRuntimeStatus
	ApplyGeoIPDatabase(*geoip.Database, uint64) error
	RollbackGeoIP(uint64) error
}

func applyHelperGeoIP(engine NetworkEngine, request GeoIPRequest) error {
	owner, ok := engine.(geoIPOwner)
	if !ok {
		if request.Builtin {
			return nil
		}
		return errors.New("network helper engine does not support GeoIP updates")
	}
	var database *geoip.Database
	var err error
	if request.Builtin {
		database = geoip.Builtin()
		if len(request.Data) > 0 || request.SHA256 != database.Metadata().SHA256 {
			return errors.New("invalid builtin GeoIP marker")
		}
	} else if request.Format == "mmdb" {
		database, err = geoip.LoadMMDB(bytes.NewReader(request.Data), request.SHA256, request.Provider)
		if err != nil {
			return err
		}
	} else {
		if request.Format != "" && request.Format != "kone-json" {
			return errors.New("unsupported GeoIP data format")
		}
		database, err = geoip.Load(bytes.NewReader(request.Data), request.SHA256)
		if err != nil {
			return err
		}
	}
	version := request.BaseVersion
	if version == 0 {
		version = owner.GeoIPStatus().PolicyVersion
	}
	return owner.ApplyGeoIPDatabase(database, version)
}
func (s *helperService) GeoIP(request GeoIPRequest, _ *Empty) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	return applyHelperGeoIP(engine, request)
}
func (s *helperService) GeoIPStatus(_ Empty, reply *kone.GeoIPRuntimeStatus) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	owner, ok := engine.(geoIPOwner)
	if !ok {
		return errors.New("GeoIP status unavailable")
	}
	*reply = owner.GeoIPStatus()
	return nil
}
func (s *helperService) GeoIPRollback(version uint64, _ *Empty) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	owner, ok := engine.(geoIPOwner)
	if !ok {
		return errors.New("GeoIP rollback unavailable")
	}
	return owner.RollbackGeoIP(version)
}

type diagnosticOwner interface {
	ProbeDiagnosticVersion(context.Context, string, string, bool, uint64) (kone.DiagnosticResult, error)
}

// Keep a distinct RPC method for UDP. Older helpers ignore unknown gob fields
// in ProbeRequest; sending them an Options-only UDP request could run TCP.
func (s *helperService) ProbeUDP(request ProbeRequest, reply *kone.DiagnosticResult) error {
	if request.Options.Protocol != "udp" {
		return errors.New("UDP diagnostic RPC requires protocol udp")
	}
	return s.Probe(request, reply)
}

func (s *helperService) Probe(request ProbeRequest, reply *kone.DiagnosticResult) error {
	if request.ID == "" || len(request.ID) > 64 {
		return errors.New("invalid diagnostic request identity")
	}
	if err := kone.ValidateDiagnosticTarget(request.Target); err != nil {
		return err
	}
	options := request.Options
	if options.Protocol == "" {
		options.TLS = request.TLS
	}
	options, err := options.Normalize()
	if err != nil {
		return err
	}
	engine, err := s.current()
	if err != nil {
		return err
	}
	owner, ok := engine.(diagnosticOwner)
	if !ok {
		return errors.New("helper engine diagnostics are unavailable")
	}
	budget := time.Duration(request.TimeoutMS) * time.Millisecond
	if budget <= 0 || budget > 5*time.Second {
		budget = 5 * time.Second
	}
	if !request.Deadline.IsZero() {
		remaining := time.Until(request.Deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		if remaining < budget {
			budget = remaining
		}
	}
	ctx, cancel := context.WithTimeout(s.ctx, budget)
	s.mu.Lock()
	for id, when := range s.canceledProbes {
		if time.Since(when) > 10*time.Second {
			delete(s.canceledProbes, id)
		}
	}
	if _, canceled := s.canceledProbes[request.ID]; canceled {
		delete(s.canceledProbes, request.ID)
		s.mu.Unlock()
		cancel()
		return context.Canceled
	}
	if s.probes == nil {
		s.probes = map[string]context.CancelFunc{}
	}
	if len(s.probes) >= 8 || s.probes[request.ID] != nil {
		s.mu.Unlock()
		cancel()
		return errors.New("helper diagnostic capacity is busy")
	}
	s.probes[request.ID] = cancel
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); delete(s.probes, request.ID); s.mu.Unlock() }()
	if request.ReportProgress && s.events != nil {
		s.mu.Lock()
		if s.probeProgressSlots == nil {
			s.probeProgressSlots = make(chan struct{}, 8)
		}
		slots := s.probeProgressSlots
		s.mu.Unlock()
		progress := helperProbeProgress{client: s.events, id: request.ID, slots: slots}
		ctx = kone.WithDiagnosticProgress(ctx, func(result kone.DiagnosticResult) { progress.publish(ctx, result) })
	}
	if options.Protocol == "udp" {
		udpOwner, ok := engine.(interface {
			ProbeDiagnosticRequestVersion(context.Context, string, string, kone.DiagnosticOptions, uint64) (kone.DiagnosticResult, error)
		})
		if !ok {
			return errors.New("helper engine UDP diagnostics are unavailable")
		}
		*reply, err = udpOwner.ProbeDiagnosticRequestVersion(ctx, request.Outbound, request.Target, options, request.ExpectedVersion)
	} else {
		*reply, err = owner.ProbeDiagnosticVersion(ctx, request.Outbound, request.Target, options.TLS, request.ExpectedVersion)
	}
	if err != nil {
		return errors.New(helperError(err))
	}
	return nil
}
func (s *helperService) CancelProbe(id string, _ *Empty) error {
	s.mu.Lock()
	cancel := s.probes[id]
	if cancel == nil && id != "" && len(id) <= 64 {
		if s.canceledProbes == nil {
			s.canceledProbes = map[string]time.Time{}
		}
		if len(s.canceledProbes) >= 64 {
			var oldest string
			var when time.Time
			for candidate, value := range s.canceledProbes {
				if when.IsZero() || value.Before(when) {
					oldest, when = candidate, value
				}
			}
			delete(s.canceledProbes, oldest)
		}
		s.canceledProbes[id] = time.Now()
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}
func (s *helperService) Stop(_ Empty, reply *StopReply) error {
	defer func() { s.flushLogs(); reply.LogsDegraded = s.logsDegraded() }()
	s.logEvent(slog.LevelInfo, "Network helper stopping capture", slog.String("stage", "stop"))
	s.mu.Lock()
	cancel := s.runCancel
	var cancelProbes []context.CancelFunc
	for _, stop := range s.probes {
		cancelProbes = append(cancelProbes, stop)
	}
	s.mu.Unlock()
	for _, stop := range cancelProbes {
		stop()
	}
	if cancel != nil {
		cancel()
	}
	engine, err := s.current()
	if err != nil {
		return nil
	}
	if err = engine.Close(); err != nil {
		return errors.New(helperError(err))
	}
	query := kone.TrafficQuery{Limit: 500}
	reply.Traffic.Traffic, reply.Traffic.Sankey, err = engine.TrafficData(query, kone.SankeyOptions{Window: time.Second, Metric: "total"})
	if err != nil {
		return err
	}
	_, reply.Cumulative, err = engine.TrafficData(query, kone.SankeyOptions{Metric: "cumulative"})
	if err != nil {
		return err
	}
	reply.DNS.Status, reply.DNS.Queries, err = engine.DNSData()
	reply.Identity.Name, reply.Identity.Index, reply.Identity.Known = engine.CaptureDeviceIdentity()
	return err
}

// ServeHelper is reachable only over authenticated private IPC transports.
// Losing either parent connection cancels Run and executes its full rollback.
// Its factory injection is for isolated tests and does not expose a public API.
func ServeHelper(ctx context.Context, commands, events io.ReadWriteCloser, factory EngineFactory, logging ...HelperLogging) error {
	return serveHelper(ctx, commands, events, factory, kone.RecoverSystemDNS, logging...)
}

func serveHelper(ctx context.Context, commands, events io.ReadWriteCloser, factory EngineFactory, recoverDNS func(context.Context, string) error, logging ...HelperLogging) error {
	if commands == nil || events == nil {
		return errors.New("private helper requires both IPC streams")
	}
	if factory == nil {
		factory = func(cfg *kone.KoneConfig) (NetworkEngine, error) { return kone.FromConfig(cfg) }
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer commands.Close()
	defer events.Close()
	commands = disconnectStream{ReadWriteCloser: commands, disconnected: cancel}
	events = disconnectStream{ReadWriteCloser: events, disconnected: cancel}
	service := &helperService{ctx: ctx, factory: factory, events: rpc.NewClient(events), recoverDNS: recoverDNS}
	if len(logging) > 0 && logging[0].Store != nil {
		service.logForwarder = &helperLogForwarder{store: logging[0].Store, client: service.events}
		service.configureLogs = logging[0].Configure
		go service.pumpLogs(ctx)
	}
	defer service.events.Close()
	server := rpc.NewServer()
	if err := server.RegisterName("Network", service); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { commands.Close(); events.Close() })
	defer stop()
	server.ServeConn(commands)
	cancel()
	service.mu.Lock()
	engine := service.engine
	cancelRun := service.runCancel
	service.mu.Unlock()
	if cancelRun != nil {
		cancelRun()
	}
	if engine != nil {
		return engine.Close()
	}
	return nil
}

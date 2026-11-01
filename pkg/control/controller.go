package control

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
	"github.com/xjdrew/kone/pkg/process"
)

type Engine interface {
	Run(context.Context) error
	Close() error
	Ready() <-chan struct{}
	Reload(*kone.KoneConfig) error
	SetTrafficObserver(*kone.TrafficObserver) error
}
type Factory func(*kone.KoneConfig) (Engine, error)

// CaptureData is implemented by local and privilege-separated engines. A
// transport error means unavailable data, never a successful empty snapshot.
type CaptureData interface {
	TrafficData(kone.TrafficQuery, kone.SankeyOptions) (kone.TrafficSnapshot, kone.SankeySnapshot, error)
	FlowRecord(string) (kone.FlowRecord, bool, error)
	DNSData() (kone.DNSRuntimeStatus, []kone.DNSQueryEvent, error)
	ClearObservation() error
}
type Options struct {
	Directory                string
	Version                  string
	Factory                  Factory
	Preflight                func(context.Context, *kone.KoneConfig) kone.PreflightReport
	Probe                    func(context.Context, *kone.KoneConfig, string, string, bool) ProbeResult
	ProbeUDP                 func(context.Context, *kone.KoneConfig, string, string, kone.DiagnosticOptions) ProbeResult
	InspectSystemDNSRecovery func(context.Context) ([]kone.SystemDNSRecoveryEntry, error)
	RecoverSystemDNS         func(context.Context, string) error
	Now                      func() time.Time
	ConfigureLogging         func(kone.GeneralConfig) error
	LogStore                 *logstore.Store
}
type Controller struct {
	mu                            sync.Mutex
	actions                       sync.Mutex
	directory, version            string
	doc, confirmed                Document
	previousConfirmed             Document
	runningVersion                uint64
	engine                        Engine
	dataSource                    CaptureData
	engineCancel                  context.CancelFunc
	engineDone                    chan struct{}
	state, lastError, configError string
	observer                      *kone.TrafficObserver
	factory                       Factory
	preflight                     func(context.Context, *kone.KoneConfig) kone.PreflightReport
	probe                         func(context.Context, *kone.KoneConfig, string, string, bool) ProbeResult
	probeUDP                      func(context.Context, *kone.KoneConfig, string, string, kone.DiagnosticOptions) ProbeResult
	diagnosticRate                rateWindow
	diagnosticAdmission           sync.Mutex
	inspectSystemDNSRecovery      func(context.Context) ([]kone.SystemDNSRecoveryEntry, error)
	recoverSystemDNS              func(context.Context, string) error
	now                           func() time.Time
	bootstrap                     string
	bootstrapExpiry               time.Time
	sessions                      map[string]*Session
	pairs                         map[string]Pairing
	operations                    map[string]*Operation
	operationOrder                []string
	requestKeys                   map[string]string
	probeSlots                    chan struct{}
	lan                           *lanServer
	address                       string
	closed                        bool
	closeOnce                     sync.Once
	closeErr                      error
	cancel                        context.CancelFunc
	ctx                           context.Context
	requestRates                  map[string]rateWindow
	configureLogging              func(kone.GeneralConfig) error
	logs                          *logstore.Store
	health                        *outboundHealthStore
	geoIPCache                    geoIPStatusCache
	credentials                   *passwordCredentials
}
type State struct {
	ControlState     string         `json:"control_state"`
	DataState        string         `json:"data_state"`
	State            string         `json:"state"`
	Version          string         `json:"version"`
	SavedVersion     uint64         `json:"saved_version"`
	RunningVersion   uint64         `json:"running_version"`
	ConfirmedVersion uint64         `json:"confirmed_version"`
	LastError        string         `json:"last_error,omitempty"`
	ConfigError      string         `json:"config_error,omitempty"`
	Host             string         `json:"host"`
	Scope            string         `json:"scope"`
	Capabilities     map[string]any `json:"capabilities"`
	Time             time.Time      `json:"time"`
	CaptureLocked    bool           `json:"capture_locked"`
}
type Operation struct {
	ID       string     `json:"id"`
	Kind     string     `json:"kind"`
	Status   string     `json:"status"`
	Stage    string     `json:"stage"`
	Started  time.Time  `json:"started_at"`
	Finished *time.Time `json:"finished_at,omitempty"`
	Result   any        `json:"result,omitempty"`
	Error    string     `json:"error,omitempty"`
	cancel   context.CancelFunc
}

func New(options Options) (*Controller, error) {
	if options.Directory == "" {
		var err error
		options.Directory, err = DefaultDirectory()
		if err != nil {
			return nil, err
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Factory == nil {
		options.Factory = func(cfg *kone.KoneConfig) (Engine, error) {
			repository, err := geoip.OpenRepository(filepath.Join(options.Directory, "geoip"))
			if err != nil {
				return nil, errors.New("saved GeoIP data needs repair before capture can start")
			}
			return kone.FromConfig(cfg, kone.WithGeoIPDatabase(repository.Current()))
		}
	}
	if options.Preflight == nil {
		options.Preflight = kone.Preflight
	}
	if options.Probe == nil {
		options.Probe = probeTarget
	}
	if options.ProbeUDP == nil {
		options.ProbeUDP = probeUDPTarget
	}
	if options.InspectSystemDNSRecovery == nil {
		options.InspectSystemDNSRecovery = kone.InspectSystemDNSRecovery
	}
	if options.RecoverSystemDNS == nil {
		options.RecoverSystemDNS = kone.RecoverSystemDNS
	}
	if err := os.MkdirAll(options.Directory, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{directory: options.Directory, version: options.Version, factory: options.Factory, preflight: options.Preflight, probe: options.Probe, now: options.Now, state: "paused", bootstrap: randomToken(), bootstrapExpiry: options.Now().Add(5 * time.Minute), sessions: map[string]*Session{}, pairs: map[string]Pairing{}, operations: map[string]*Operation{}, requestKeys: map[string]string{}, probeSlots: make(chan struct{}, 4), ctx: ctx, cancel: cancel}
	c.inspectSystemDNSRecovery, c.recoverSystemDNS = options.InspectSystemDNSRecovery, options.RecoverSystemDNS
	c.probeUDP = options.ProbeUDP
	if err := c.initAuthentication(); err != nil {
		cancel()
		return nil, err
	}
	c.requestRates = map[string]rateWindow{}
	c.logs = options.LogStore
	if c.logs == nil {
		c.logs = logstore.New()
	}
	c.observer = kone.NewTrafficObserver(kone.ObservationOptions{Capacity: 2048, Retention: time.Hour})
	doc, err := readDocument(c.settingsPath())
	if errors.Is(err, os.ErrNotExist) {
		doc = Document{Version: 1, Config: managementDefaults(), Inbound: Inbound{"tun-main", "TUN", true}}
		assignIDs(doc.Config)
		if err = writeDocument(c.settingsPath(), doc); err != nil {
			cancel()
			return nil, err
		}
	} else if err != nil {
		c.configError = "Saved settings need repair; the original file has been preserved"
		doc = Document{Version: 1, Config: managementDefaults(), Inbound: Inbound{"tun-main", "TUN", false}}
		for _, path := range []string{c.confirmedPath(), c.settingsPath() + ".previous", c.confirmedPath() + ".previous"} {
			if fallback, backupErr := readDocument(path); backupErr == nil && fallback.Version >= doc.Version {
				doc = fallback
				c.configError = "Saved settings need repair; showing the last valid backup while preserving the original file"
			}
		}
	}
	c.doc = doc
	c.configureLogging = options.ConfigureLogging
	if c.configureLogging != nil {
		if err := c.configureLogging(doc.Config.General); err != nil {
			cancel()
			return nil, err
		}
	}
	if confirmed, e := readDocument(c.confirmedPath()); e == nil {
		c.confirmed = confirmed
	}
	if previous, e := readDocument(c.confirmedPath() + ".previous"); e == nil {
		c.previousConfirmed = previous
	}
	if _, e := os.Stat(c.journalPath()); e == nil {
		c.state = "recovery_required"
		c.lastError = "The previous capture did not finish cleanly; inspect recovery before starting"
	}
	return c, nil
}
func (c *Controller) settingsPath() string { return filepath.Join(c.directory, "settings.json") }

func managementDefaults() *kone.KoneConfig {
	cfg := kone.DefaultConfig()
	cfg.Rule = []kone.RuleConfig{{ID: "rule-default-direct", Source: "default", Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	cfg.DNS.System = kone.SupportsSystemDNS()
	return cfg
}
func (c *Controller) confirmedPath() string  { return filepath.Join(c.directory, "confirmed.json") }
func (c *Controller) journalPath() string    { return filepath.Join(c.directory, "capture.json") }
func (c *Controller) BootstrapToken() string { c.mu.Lock(); defer c.mu.Unlock(); return c.bootstrap }

// LocalAccessURL is for trusted native UI actions, never an HTTP route.
// Initial setup renews its one-use fragment. Configured profiles open a clean
// login URL; a native shortcut never bypasses the management password.
func (c *Controller) LocalAccessURL() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.address == "" {
		return "", errors.New("local management is unavailable")
	}
	if len(c.credentials.Hash) != 0 {
		c.bootstrap = ""
		return "http://" + c.address + "/", nil
	}
	c.bootstrap = randomToken()
	c.bootstrapExpiry = c.now().Add(5 * time.Minute)
	return "http://" + c.address + "/#token=" + c.bootstrap, nil
}

func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	host, _ := os.Hostname()
	control := "ready"
	if c.configError != "" {
		control = "configuration_repair"
	}
	if c.closed {
		control = "stopped"
	}
	capabilities := map[string]any{
		"inbounds": []string{"tun"}, "stacks": kone.SupportedStacks(),
		"tcp": true, "udp_direct": true, "udp_proxy": true, "proxy_udp_schemes": []string{"socks5", "ss"},
		"ipv6": kone.SupportsIPv6Capture(), "ipv6_enabled": c.doc.Config.Core.IPv6Network != "",
		"system_dns": kone.SupportsSystemDNS(), "system_dns_enabled": c.doc.Config.DNS.System,
		"process_attribution": process.Supported(), "process_scope": "best effort for local IPv4 sockets; IPv6 and unverified owners remain unknown; remote sources remain remote",
		"tls_lan": true, "persistent_config": true, "statistics": "business payload bytes", "temporary_rules": true, "temporary_rule_scope": "domain rules only",
	}
	return State{ControlState: control, DataState: c.state, State: c.state, Version: c.version, SavedVersion: c.doc.Version, RunningVersion: c.runningVersion, ConfirmedVersion: c.confirmed.Version, LastError: c.lastError, ConfigError: c.configError, Host: host, Scope: "Only traffic entering KONE; DNS, diagnostics and business traffic are separate", Capabilities: capabilities, Time: c.now(), CaptureLocked: c.captureLocked()}
}

func (c *Controller) Document() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	credentials := map[string]any{}
	for _, o := range c.doc.Config.Outbounds {
		credentials[o.Name] = map[string]any{"configured": hasCredentials(o.URL)}
	}
	return map[string]any{"version": c.doc.Version, "config": jsonConfig(c.doc.Config), "inbound": c.doc.Inbound, "credential_state": credentials, "confirmed_version": c.confirmed.Version, "running_version": c.runningVersion, "config_error": c.configError, "capture_locked": c.captureLocked(), "direct_only_confirmed": c.doc.DirectOnlyConfirmed}
}

// Caller holds c.mu; startup is locked even while privilege authorization is pending.
func (c *Controller) captureLocked() bool {
	return c.engine != nil || c.state == "starting" || c.state == "pausing"
}

func (c *Controller) Validate(request SaveRequest) (map[string]any, error) {
	c.mu.Lock()
	current := cloneDocument(c.doc)
	c.mu.Unlock()
	next, err := prepareDocument(request, current)
	if err != nil {
		return nil, err
	}
	restart := restartRequired(next, current)
	return map[string]any{"valid": true, "restart_required": restart, "issues": []any{}, "impact": map[string]any{"established_flows": "retain their current snapshot", "new_flows": "use the new version after apply", "restart_interrupts_connections": restart}}, nil
}

func restartRequired(next, current Document) bool {
	return next.Inbound != current.Inbound || !reflect.DeepEqual(next.Config.Core, current.Config.Core) || !reflect.DeepEqual(next.Config.DNS, current.Config.DNS) || !reflect.DeepEqual(next.Config.General, current.Config.General) || next.Config.GeoIP != current.Config.GeoIP || cidrChanges(next.Config, current.Config)
}

func cidrChanges(a, b *kone.KoneConfig) bool {
	routes := func(cfg *kone.KoneConfig) []kone.RuleConfig {
		var rules []kone.RuleConfig
		for _, r := range cfg.Rule {
			if r.Schema == "IP-CIDR" || r.Schema == "IP-CIDR6" {
				rules = append(rules, r)
			}
		}
		return rules
	}
	return !reflect.DeepEqual(routes(a), routes(b))
}

func (c *Controller) Save(request SaveRequest) (map[string]any, error) {
	c.actions.Lock()
	defer c.actions.Unlock()
	return c.saveLocked(request)
}

// Caller holds c.actions so resets and lifecycle changes cannot race a save.
func (c *Controller) saveLocked(request SaveRequest) (map[string]any, error) {
	c.mu.Lock()
	current := cloneDocument(c.doc)
	repair := c.configError != ""
	closed := c.closed
	engine := c.engine
	c.mu.Unlock()
	if closed {
		return nil, errors.New("application is stopping")
	}
	next, err := prepareDocument(request, current)
	if err != nil {
		return nil, err
	}
	if engine != nil && restartRequired(next, current) {
		return nil, ErrCaptureLocked
	}
	// Check disk revision as well as browser revision to reject external edits.
	if disk, e := readDocument(c.settingsPath()); e == nil && !sameDocument(disk, current) {
		return nil, ErrConflict
	} else if e != nil && !repair {
		return nil, errors.New("saved settings changed or became unreadable; reload before saving")
	}
	if repair {
		if err = brokenBackup(c.settingsPath()); err != nil {
			return nil, err
		}
	} else {
		if err = writeDocument(c.settingsPath()+".previous", current); err != nil {
			return nil, err
		}
	}
	if err = writeDocument(c.settingsPath(), next); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.doc = next
	c.configError = ""
	c.mu.Unlock()
	value := c.Document()
	value["applied"] = false
	if engine != nil {
		if directOnly(next.Config) && !next.DirectOnlyConfirmed {
			value["apply_error"] = "Saved, but confirm direct-only capture before applying"
			return value, nil
		}
		applyCtx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
		err = c.applyLocked(applyCtx)
		cancel()
		value = c.Document()
		value["applied"] = c.State().RunningVersion == next.Version
		if err != nil {
			value["apply_error"] = safeMessage(err, next.Config)
		}
	}
	return value, nil
}

func engineConfig(doc Document) *kone.KoneConfig {
	cfg := cloneDocument(doc).Config
	return cfg
}

func (c *Controller) Preflight(ctx context.Context) kone.PreflightReport {
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	err := c.configError
	state := c.state
	c.mu.Unlock()
	if err != "" || state == "recovery_required" || state == "recovery_failed" {
		return kone.PreflightReport{Ready: false, Issues: []kone.PreflightIssue{{Code: "recovery", Severity: "error", Message: "Repair saved settings and inspect previous capture before enabling"}}}
	}
	return c.preflight(ctx, engineConfig(doc))
}

func (c *Controller) Start(ctx context.Context) error {
	c.actions.Lock()
	defer c.actions.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("application is stopping")
	}
	if c.engine != nil {
		state := c.state
		c.mu.Unlock()
		if state == "running" {
			return nil
		}
		return errors.New("an engine operation is already in progress")
	}
	doc := cloneDocument(c.doc)
	bad := c.configError != "" || c.state == "recovery_required" || c.state == "recovery_failed"
	c.mu.Unlock()
	if bad {
		return errors.New("repair configuration or recovery state before enabling capture")
	}
	check := c.readiness(ctx, doc, "paused", "")
	if !check.Ready {
		messages := make([]string, 0, len(check.Blockers))
		for _, issue := range check.Blockers {
			messages = append(messages, issue.Message)
		}
		return c.startFailure(errors.New(strings.Join(messages, "; ")), doc.Config)
	}
	if c.configureLogging != nil {
		if err := c.configureLogging(doc.Config.General); err != nil {
			return c.startFailure(err, doc.Config)
		}
	}
	c.mu.Lock()
	c.state = "starting"
	c.lastError = ""
	c.mu.Unlock()
	engine, err := c.factory(engineConfig(doc))
	if err != nil {
		return c.startFailure(err, doc.Config)
	}
	observer := kone.NewTrafficObserver(kone.ObservationOptions{Capacity: 2048, Retention: time.Hour})
	if logged, ok := engine.(interface{ SetLogStore(*logstore.Store) error }); ok {
		if err = logged.SetLogStore(c.logs); err != nil {
			engine.Close()
			return c.startFailure(err, doc.Config)
		}
	}
	if err = engine.SetTrafficObserver(observer); err != nil {
		engine.Close()
		return c.startFailure(err, doc.Config)
	}
	runID := randomToken()
	if versioned, ok := engine.(interface{ SetConfigVersion(uint64) error }); ok {
		if err = versioned.SetConfigVersion(doc.Version); err != nil {
			engine.Close()
			return c.startFailure(err, doc.Config)
		}
	}
	if recorder, ok := engine.(interface {
		SetCaptureRecorder(func(string, int) error) error
	}); ok {
		if err = recorder.SetCaptureRecorder(func(name string, index int) error { return c.recordRecoveryDevice(runID, name, index) }); err != nil {
			engine.Close()
			return c.startFailure(err, doc.Config)
		}
	}
	if err = c.writeRecoveryJournal(doc.Config, runID); err != nil {
		engine.Close()
		return c.startFailure(err, doc.Config)
	}
	engineCtx, cancel := context.WithCancel(c.ctx)
	done := make(chan struct{})
	result := make(chan error, 1)
	c.mu.Lock()
	c.engine = engine
	c.dataSource, _ = engine.(CaptureData)
	c.engineCancel = cancel
	c.engineDone = done
	c.observer = observer
	c.mu.Unlock()
	go func() {
		e := engine.Run(engineCtx)
		cleanupErr := engine.Close()
		if cleanupErr == nil {
			cleanupErr = c.removeRecoveryJournal(runID)
		}
		c.mu.Lock()
		if c.engine == engine {
			c.engine = nil
			c.engineCancel = nil
			c.runningVersion = 0
			c.state = "paused"
			if e != nil {
				c.lastError = safeMessage(e, doc.Config)
			}
			if cleanupErr != nil {
				c.state = "recovery_failed"
				c.lastError = safeMessage(cleanupErr, doc.Config)
			}
		}
		c.mu.Unlock()
		result <- errors.Join(e, cleanupErr)
		close(done)
	}()
	select {
	case <-engine.Ready():
		if err = c.confirm(doc); err != nil {
			cancel()
			engine.Close()
			<-done
			return c.startFailure(err, doc.Config)
		}
		c.mu.Lock()
		if c.engine != engine {
			c.mu.Unlock()
			return errors.New("engine stopped during startup")
		}
		c.state = "running"
		c.runningVersion = doc.Version
		c.mu.Unlock()
		if device, ok := engine.(interface{ CaptureDeviceIdentity() (string, int, bool) }); ok {
			if name, _, known := device.CaptureDeviceIdentity(); known {
				go c.watchCaptureNetwork(engineCtx, engine, name)
			}
		}
		return nil
	case err = <-result:
		if err == nil {
			err = errors.New("engine stopped before ready")
		}
		return c.startFailure(err, doc.Config)
	case <-ctx.Done():
		cancel()
		engine.Close()
		<-done
		return ctx.Err()
	case <-time.After(20 * time.Second):
		cancel()
		engine.Close()
		<-done
		return c.startFailure(errors.New("capture startup timed out"), doc.Config)
	}
}

func (c *Controller) watchCaptureNetwork(ctx context.Context, engine Engine, name string) {
	for change := range WatchNetworkChanges(ctx, name, 5*time.Second) {
		c.actions.Lock()
		c.mu.Lock()
		current := c.engine == engine
		c.mu.Unlock()
		if current {
			stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := c.pauseLocked(stopCtx)
			cancel()
			if err == nil {
				c.mu.Lock()
				c.lastError = "Network context changed; capture was paused. Run preflight before enabling it again (" + change.Kind + ")"
				c.mu.Unlock()
			}
		}
		c.actions.Unlock()
	}
}
func (c *Controller) startFailure(err error, cfg *kone.KoneConfig) error {
	c.mu.Lock()
	c.lastError = safeMessage(err, cfg)
	if c.state != "recovery_failed" {
		c.state = "paused"
	}
	c.mu.Unlock()
	c.logs.Append(logstore.Record{Level: "ERROR", Source: "management", Message: "Capture startup failed", Attrs: map[string]any{"stage": "start", "error": safeMessage(err, cfg)}})
	return err
}

func (c *Controller) Pause(ctx context.Context) error {
	c.actions.Lock()
	defer c.actions.Unlock()
	return c.pauseLocked(ctx)
}
func (c *Controller) pauseLocked(ctx context.Context) error {
	c.mu.Lock()
	engine, cancel, done := c.engine, c.engineCancel, c.engineDone
	failed, message := c.state == "recovery_failed", c.lastError
	if engine != nil {
		c.state = "pausing"
	}
	c.mu.Unlock()
	if engine == nil {
		if failed {
			return errors.New(message)
		}
		return nil
	}
	cancel()
	err := engine.Close()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err != nil {
		c.mu.Lock()
		c.state = "recovery_failed"
		c.lastError = safeMessage(err, c.doc.Config)
		c.mu.Unlock()
	}
	return err
}

func (c *Controller) Apply(ctx context.Context) error {
	c.actions.Lock()
	defer c.actions.Unlock()
	return c.applyLocked(ctx)
}

func (c *Controller) applyLocked(ctx context.Context) error {
	c.mu.Lock()
	engine := c.engine
	doc := cloneDocument(c.doc)
	c.mu.Unlock()
	if engine == nil {
		return errors.New("capture is paused; enable it explicitly to apply saved settings")
	}
	if !doc.Inbound.Enabled {
		return c.pauseLocked(ctx)
	}
	if directOnly(doc.Config) && !doc.DirectOnlyConfirmed {
		return errors.New("confirm direct-only capture before applying")
	}
	var err error
	if versioned, ok := engine.(interface {
		ReloadVersion(*kone.KoneConfig, uint64) error
	}); ok {
		err = versioned.ReloadVersion(engineConfig(doc), doc.Version)
	} else {
		err = engine.Reload(engineConfig(doc))
	}
	if err != nil {
		c.mu.Lock()
		c.lastError = safeMessage(err, doc.Config)
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	c.runningVersion = doc.Version
	c.lastError = ""
	c.mu.Unlock()
	if err := c.confirm(doc); err != nil {
		return errors.New("runtime updated, but confirmation could not be saved")
	}
	return nil
}

func (c *Controller) confirm(doc Document) error {
	c.mu.Lock()
	previous := cloneDocument(c.confirmed)
	c.mu.Unlock()
	if previous.Config != nil && previous.Version != doc.Version {
		if err := writeDocument(c.confirmedPath()+".previous", previous); err != nil {
			return err
		}
	}
	if err := writeDocument(c.confirmedPath(), doc); err != nil {
		return err
	}
	c.mu.Lock()
	if previous.Config != nil && previous.Version != doc.Version {
		c.previousConfirmed = previous
	}
	c.confirmed = doc
	c.mu.Unlock()
	return nil
}

func (c *Controller) Undo(base uint64) (map[string]any, error) {
	c.mu.Lock()
	confirmed := cloneDocument(c.confirmed)
	if c.doc.Version == c.confirmed.Version && c.previousConfirmed.Config != nil {
		confirmed = cloneDocument(c.previousConfirmed)
	}
	c.mu.Unlock()
	if confirmed.Config == nil {
		return nil, errors.New("no previously applied configuration is available")
	}
	data, _ := toml.Marshal(confirmed.Config)
	var configuration map[string]any
	_ = toml.Unmarshal(data, &configuration)
	return c.Save(SaveRequest{BaseVersion: base, Config: configuration, Inbound: confirmed.Inbound})
}

func (c *Controller) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		lan := c.lan
		c.mu.Unlock()
		if lan != nil {
			lan.close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c.closeErr = c.Pause(ctx)
	})
	return c.closeErr
}

func hasCredentials(raw string) bool { u, e := url.Parse(raw); return e == nil && u.User != nil }

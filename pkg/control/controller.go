package control

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
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
	Directory string
	Version   string
	Factory   Factory
	Preflight func(context.Context, *kone.KoneConfig) kone.PreflightReport
	Probe     func(context.Context, *kone.KoneConfig, string, string, bool) ProbeResult
	Now       func() time.Time
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
	if err := os.MkdirAll(options.Directory, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{directory: options.Directory, version: options.Version, factory: options.Factory, preflight: options.Preflight, probe: options.Probe, now: options.Now, state: "paused", bootstrap: randomToken(), bootstrapExpiry: options.Now().Add(5 * time.Minute), sessions: map[string]*Session{}, pairs: map[string]Pairing{}, operations: map[string]*Operation{}, requestKeys: map[string]string{}, probeSlots: make(chan struct{}, 4), ctx: ctx, cancel: cancel}
	c.requestRates = map[string]rateWindow{}
	c.observer = kone.NewTrafficObserver(kone.ObservationOptions{Capacity: 2048, Retention: time.Hour})
	doc, err := readDocument(c.settingsPath())
	if errors.Is(err, os.ErrNotExist) {
		doc = Document{Version: 1, Config: kone.DefaultConfig(), Inbound: Inbound{"tun-main", "TUN", false}}
		assignIDs(doc.Config)
		if err = writeDocument(c.settingsPath(), doc); err != nil {
			cancel()
			return nil, err
		}
	} else if err != nil {
		c.configError = "Saved settings need repair; the original file has been preserved"
		doc = Document{Version: 1, Config: kone.DefaultConfig(), Inbound: Inbound{"tun-main", "TUN", false}}
	}
	c.doc = doc
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
func (c *Controller) settingsPath() string   { return filepath.Join(c.directory, "settings.json") }
func (c *Controller) confirmedPath() string  { return filepath.Join(c.directory, "confirmed.json") }
func (c *Controller) journalPath() string    { return filepath.Join(c.directory, "capture.json") }
func (c *Controller) BootstrapToken() string { c.mu.Lock(); defer c.mu.Unlock(); return c.bootstrap }

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
	return State{control, c.state, c.state, c.version, c.doc.Version, c.runningVersion, c.confirmed.Version, c.lastError, c.configError, host, "Only traffic entering KONE; DNS, diagnostics and business traffic are separate", map[string]any{"inbounds": []string{"tun"}, "stacks": kone.SupportedStacks(), "tcp": true, "udp_direct": true, "udp_proxy": true, "proxy_udp_schemes": []string{"socks5", "ss"}, "ipv6": kone.SupportsIPv6Capture(), "ipv6_enabled": c.doc.Config.Core.IPv6Network != "", "process_attribution": process.Supported(), "process_scope": "best effort for locally owned sockets; remote or unverified owners remain unknown", "tls_lan": true, "persistent_config": true, "statistics": "business payload bytes", "temporary_rules": false}, c.now()}
}

func (c *Controller) Document() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	credentials := map[string]any{}
	for _, o := range c.doc.Config.Outbounds {
		credentials[o.Name] = map[string]any{"configured": hasCredentials(o.URL)}
	}
	return map[string]any{"version": c.doc.Version, "config": jsonConfig(c.doc.Config), "inbound": c.doc.Inbound, "credential_state": credentials, "confirmed_version": c.confirmed.Version, "running_version": c.runningVersion, "config_error": c.configError}
}

func (c *Controller) Validate(request SaveRequest) (map[string]any, error) {
	c.mu.Lock()
	current := cloneDocument(c.doc)
	c.mu.Unlock()
	next, err := prepareDocument(request, current)
	if err != nil {
		return nil, err
	}
	restart := !reflect.DeepEqual(next.Config.Core, current.Config.Core) || !reflect.DeepEqual(next.Config.DNS, current.Config.DNS) || !reflect.DeepEqual(next.Config.General, current.Config.General) || cidrChanges(next.Config, current.Config)
	return map[string]any{"valid": true, "restart_required": restart, "issues": []any{}, "impact": map[string]any{"established_flows": "retain their current snapshot", "new_flows": "use the new version after apply", "restart_interrupts_connections": restart}}, nil
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
	c.mu.Lock()
	current := cloneDocument(c.doc)
	repair := c.configError != ""
	c.mu.Unlock()
	next, err := prepareDocument(request, current)
	if err != nil {
		return nil, err
	}
	// Check disk revision as well as browser revision to reject external edits.
	if disk, e := readDocument(c.settingsPath()); e == nil && disk.Version != current.Version {
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
	return c.Document(), nil
}

func engineConfig(doc Document) *kone.KoneConfig {
	cfg := cloneDocument(doc).Config
	cfg.General.ManagerAddr = ""
	return cfg
}

func (c *Controller) Preflight(ctx context.Context) kone.PreflightReport {
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	err := c.configError
	state := c.state
	c.mu.Unlock()
	if err != "" || state == "recovery_required" {
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
	bad := c.configError != "" || c.state == "recovery_required"
	c.mu.Unlock()
	if bad {
		return errors.New("repair configuration or recovery state before enabling capture")
	}
	if !doc.Inbound.Enabled {
		return errors.New("enable the TUN inbound before starting capture")
	}
	check := c.preflight(ctx, engineConfig(doc))
	if !check.Ready {
		return errors.New("preflight failed; inspect blocking issues")
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
	if engine != nil {
		c.state = "pausing"
	}
	c.mu.Unlock()
	if engine == nil {
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
	var err error
	if versioned, ok := engine.(interface {
		ReloadVersion(*kone.KoneConfig, uint64) error
	}); ok {
		err = versioned.ReloadVersion(engineConfig(doc), doc.Version)
	} else {
		err = engine.Reload(engineConfig(doc))
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.runningVersion = doc.Version
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

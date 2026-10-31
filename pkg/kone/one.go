package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type runtimeSnapshot struct {
	version   uint64
	cfg       *KoneConfig
	rule      *Rule
	outbounds *Outbounds
}
type ConfigSnapshot struct {
	Version uint64
	Config  *KoneConfig
}

type One struct {
	ip              net.IP
	subnet          *net.IPNet
	policy          atomic.Pointer[runtimeSnapshot]
	reloadMu        sync.Mutex
	mu              sync.Mutex
	started, closed bool
	cancel          context.CancelFunc
	done, ready     chan struct{}
	cleanupErr      error
	network         Network
	sockets         Sockets
	shutdownTimeout time.Duration
	readSystemDNS   func() ([]string, error)
	stackFactory    stackFactory
	flows           *flowHandler
	dnsTable        *DnsTable
	dns             *Dns
	manager         *Manager
}

type Option func(*One) error

func WithNetwork(network Network) Option {
	return func(one *One) error {
		if isNilInterface(network) {
			return errors.New("network is nil")
		}
		one.network = network
		return nil
	}
}
func WithSockets(sockets Sockets) Option {
	return func(one *One) error {
		if isNilInterface(sockets) {
			return errors.New("sockets is nil")
		}
		one.sockets = sockets
		return nil
	}
}
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(one *One) error {
		if timeout <= 0 {
			return errors.New("shutdown timeout must be positive")
		}
		one.shutdownTimeout = timeout
		return nil
	}
}

func cloneConfig(cfg *KoneConfig) *KoneConfig {
	copy := *cfg
	copy.Outbounds = slices.Clone(cfg.Outbounds)
	copy.Rule = slices.Clone(cfg.Rule)
	copy.DNS.Servers = slices.Clone(cfg.DNS.Servers)
	if data, ok := cfg.source.([]byte); ok {
		copy.source = slices.Clone(data)
	}
	return &copy
}

func (one *One) Snapshot() ConfigSnapshot {
	s := one.policy.Load()
	return ConfigSnapshot{Version: s.version, Config: cloneConfig(s.cfg)}
}
func (one *One) Ready() <-chan struct{} { return one.ready }

func (one *One) DNSSnapshot() (uint64, map[string]*DomainRecord) {
	s := one.policy.Load()
	records := one.dnsTable.Snapshot()
	for _, record := range records {
		record.Proxy = s.rule.ProxyDNS(record.Hostname, record.resolved)
	}
	return s.version, records
}

// FromConfig validates and constructs an engine without changing system state.
// Run owns every resource acquired during startup and always releases it.
func FromConfig(cfg *KoneConfig, options ...Option) (*One, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cloneConfig(cfg)
	ip, subnet, _ := net.ParseCIDR(cfg.Core.Network)
	one := &One{ip: ip.To4(), subnet: subnet, network: systemNetwork{run: runCommand, gateway: "0.0.0.0"}, sockets: &net.ListenConfig{}, stackFactory: newSingStack, shutdownTimeout: 15 * time.Second, readSystemDNS: systemDNSServers, done: make(chan struct{}), ready: make(chan struct{})}
	for _, option := range options {
		if err := option(one); err != nil {
			return nil, err
		}
	}
	dnsCfg, err := effectiveDNSConfig(cfg.DNS, one.readSystemDNS)
	if err != nil {
		return nil, err
	}
	effective := cloneConfig(cfg)
	effective.DNS = dnsCfg
	if err := effective.Validate(); err != nil {
		return nil, err
	}
	p, err := NewOutbounds(cfg.Outbounds)
	if err != nil {
		return nil, err
	}
	dialer, err := outboundDialer(cfg.Core, dnsCfg.Servers)
	if err != nil {
		return nil, err
	}
	p.dial = dialer.DialContext
	one.flows = &flowHandler{one: one}
	rule := NewRule(cfg.Rule, cfg.Outbounds)
	p.bypassEndpoints(rule)
	one.policy.Store(&runtimeSnapshot{version: 1, cfg: cfg, rule: rule, outbounds: p})
	one.dnsTable = NewDnsTable(ip, subnet)
	// The system TCP forwarder uses the address after the TUN address.
	next := netip.MustParseAddr(ip.String()).Next()
	one.dnsTable.ipPool.reserve(next)
	one.dnsTable.ttl = uint32(cfg.DNS.TTL)
	if one.dns, err = NewDns(one, dnsCfg); err != nil {
		return nil, err
	}
	one.dns.client.Dialer = dialer
	one.manager = NewManager(one, cfg)
	return one, nil
}

// Reload publishes a complete, immutable rule/proxy/config generation. Each
// request/flow retains its loaded generation even if another reload succeeds.
func (one *One) Reload(cfg *KoneConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg = cloneConfig(cfg)
	one.reloadMu.Lock()
	defer one.reloadMu.Unlock()
	one.mu.Lock()
	closed := one.closed
	one.mu.Unlock()
	if closed {
		return errors.New("engine is closed")
	}
	old := one.policy.Load()
	type routeRule struct {
		RuleConfig
		Kind OutboundType
	}
	cidrs := func(config *KoneConfig) []routeRule {
		var result []routeRule
		types, _ := validateOutbounds(config.Outbounds)
		for _, r := range config.Rule {
			if strings.EqualFold(r.Schema, "IP-CIDR") {
				result = append(result, routeRule{r, types[r.Outbound]})
			}
		}
		return result
	}
	if !reflect.DeepEqual(cfg.Core, old.cfg.Core) || !reflect.DeepEqual(cfg.DNS, old.cfg.DNS) || cfg.General != old.cfg.General || !slices.Equal(cidrs(cfg), cidrs(old.cfg)) {
		return errors.New("changes to general/core/dns or IP-CIDR routes require restart")
	}
	p, err := NewOutbounds(cfg.Outbounds)
	if err != nil {
		return err
	}
	p.dial = old.outbounds.dial
	rule := NewRule(cfg.Rule, cfg.Outbounds)
	p.bypassEndpoints(rule)
	one.policy.Store(&runtimeSnapshot{version: old.version + 1, cfg: cfg, rule: rule, outbounds: p})
	one.dnsTable.ClearNonProxyDomain()
	return nil
}

// Close is idempotent and waits for Run to finish cleanup. Run cancellation is
// also used for startup interruption; cleanup has an independent timeout.
func (one *One) Close() error {
	one.mu.Lock()
	if !one.started && !one.closed {
		one.closed = true
		close(one.done)
	}
	if one.cancel != nil {
		one.cancel()
	}
	one.mu.Unlock()
	<-one.done
	one.mu.Lock()
	defer one.mu.Unlock()
	return one.cleanupErr
}

// Serve is retained for embedders; new callers should use Run with a context.
func (one *One) Serve() error { return one.Run(context.Background()) }

func (one *One) Run(parent context.Context) (result error) {
	one.mu.Lock()
	if one.started || one.closed {
		one.mu.Unlock()
		return errors.New("engine can only run once")
	}
	one.started = true
	ctx, cancel := context.WithCancel(parent)
	one.cancel = cancel
	one.mu.Unlock()
	var device Device
	var undo undoStack
	var dnsConn net.PacketConn
	var manager net.Listener
	var stack packetStack
	var wg sync.WaitGroup
	errorsCh := make(chan error, 6)
	defer func() {
		if ctx.Err() != nil && (errors.Is(result, context.Canceled) || errors.Is(result, context.DeadlineExceeded)) {
			result = nil
		}
		cancel()
		one.reloadMu.Lock()
		one.mu.Lock()
		one.closed = true
		one.mu.Unlock()
		one.reloadMu.Unlock()
		cleanupCtx, stop := context.WithTimeout(context.Background(), one.shutdownTimeout)
		defer stop()
		// Stop admission and active flows before restoring system networking.
		var cleanup []error
		if manager != nil {
			cleanup = append(cleanup, manager.Close())
		}
		one.flows.close()
		if dnsConn != nil {
			dnsConn.Close()
		}
		if !isNilInterface(stack) {
			cleanup = append(cleanup, stack.Close())
		}
		if one.dns.started.Load() {
			cleanup = append(cleanup, one.dns.server.ShutdownContext(cleanupCtx))
		}
		if one.manager != nil && one.manager.server != nil {
			cleanup = append(cleanup, one.manager.server.Shutdown(cleanupCtx))
			one.manager.server.Close()
		}
		cleanup = append(cleanup, undo.restore(cleanupCtx))
		if device != nil {
			cleanup = append(cleanup, device.Close())
		}
		if waiter, ok := stack.(interface{ Wait() }); ok && !isNilInterface(stack) {
			waiter.Wait()
		}
		one.flows.workers.Wait()
		wg.Wait()
		one.mu.Lock()
		one.cleanupErr = errors.Join(cleanup...)
		result = errors.Join(result, one.cleanupErr)
		close(one.done)
		one.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return nil
	}
	cfg := one.policy.Load().cfg
	var err error
	opened, err := one.network.Open(ctx, cfg.Core)
	if !isNilInterface(opened) {
		device = opened
	}
	if err != nil {
		return fmt.Errorf("open TUN: %w", err)
	}
	if device == nil {
		return errors.New("network returned a nil TUN device")
	}
	cleanup, err := one.network.Configure(ctx, device, cfg.Core)
	undo.add("interface configuration", cleanup)
	if err != nil {
		return fmt.Errorf("configure TUN: %w", err)
	}
	lc := one.sockets
	if preparer, ok := one.network.(interface {
		PrepareStack(context.Context, CoreConfig) (Cleanup, error)
	}); ok {
		cleanup, err := preparer.PrepareStack(ctx, cfg.Core)
		undo.add("stack prerequisites", cleanup)
		if err != nil {
			return fmt.Errorf("prepare TUN stack: %w", err)
		}
	}
	stack, err = one.stackFactory(ctx, device, cfg.Core, one.flows, errorsCh)
	if err != nil {
		return fmt.Errorf("create TUN stack: %w", err)
	}
	if isNilInterface(stack) {
		return errors.New("stack factory returned a nil stack")
	}
	if err := stack.Start(); err != nil {
		return fmt.Errorf("start TUN stack: %w", err)
	}
	if dnsConn, err = lc.ListenPacket(ctx, "udp", one.dns.server.Addr); err != nil {
		return fmt.Errorf("DNS listener: %w", err)
	}
	if one.manager != nil {
		if manager, err = lc.Listen(ctx, "tcp", one.manager.listen); err != nil {
			return fmt.Errorf("manager listener: %w", err)
		}
		manager = &ownedListener{Listener: manager}
		one.manager.server = &http.Server{Handler: one.manager.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	}
	seen := make(map[string]bool)
	if cfg.Core.AutoRoute {
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			_, subnet, _ := net.ParseCIDR(cidr)
			cleanup, err := one.network.AddRoute(ctx, device, subnet)
			undo.add("capture route "+cidr, cleanup)
			if err != nil {
				return fmt.Errorf("add route %s: %w", cidr, err)
			}
			seen[cidr] = true
		}
	}
	for _, pattern := range one.policy.Load().rule.patterns {
		if p, ok := pattern.(IPCIDRPattern); ok && one.policy.Load().rule.OutboundType(p.Proxy()) != OutboundDirect && !seen[p.prefix.String()] {
			_, subnet, _ := net.ParseCIDR(p.prefix.String())
			routes := []*net.IPNet{subnet}
			if p.prefix.Bits() == 0 {
				routes = nil
				for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
					_, subnet, _ := net.ParseCIDR(cidr)
					routes = append(routes, subnet)
				}
			}
			for _, route := range routes {
				if seen[route.String()] {
					continue
				}
				cleanup, err := one.network.AddRoute(ctx, device, route)
				undo.add("route "+route.String(), cleanup)
				if err != nil {
					return fmt.Errorf("add route %s: %w", route, err)
				}
				seen[route.String()] = true
			}
			seen[p.prefix.String()] = true
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	start := func(name string, serve func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := serve()
			if ctx.Err() == nil {
				if err == nil {
					err = errors.New("stopped unexpectedly")
				}
				errorsCh <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	one.dns.ctx = ctx
	one.dns.server.PacketConn = dnsConn
	dnsReady := make(chan struct{})
	one.dns.server.NotifyStartedFunc = func() { one.dns.started.Store(true); close(dnsReady) }
	start("DNS", one.dns.server.ActivateAndServe)
	select {
	case <-dnsReady:
	case err := <-errorsCh:
		return err
	case <-ctx.Done():
		return nil
	}
	start("DNS cache", func() error { return one.dnsTable.Serve(ctx) })
	if one.manager != nil {
		start("manager", func() error { return one.manager.server.Serve(manager) })
	}
	close(one.ready)
	select {
	case err := <-errorsCh:
		if ctx.Err() == nil {
			return err
		}
		return nil
	case <-ctx.Done():
		return nil
	}
}

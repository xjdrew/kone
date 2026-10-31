package kone

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjdrew/kone/pkg/tcpip"
)

type runtimeSnapshot struct {
	version uint64
	cfg     *KoneConfig
	rule    *Rule
	proxies *Proxies
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
	dnsTable        *DnsTable
	dns             *Dns
	tcpRelay        *TCPRelay
	udpRelay        *UDPRelay
	tun             *TunDriver
	manager         *Manager
}

type Option func(*One) error

func WithNetwork(network Network) Option {
	return func(one *One) error {
		if network == nil {
			return errors.New("network is nil")
		}
		one.network = network
		return nil
	}
}
func WithSockets(sockets Sockets) Option {
	return func(one *One) error {
		if sockets == nil {
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
	copy.Proxy = maps.Clone(cfg.Proxy)
	copy.Rule = slices.Clone(cfg.Rule)
	copy.Core.DnsServer = slices.Clone(cfg.Core.DnsServer)
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
	one := &One{ip: ip.To4(), subnet: subnet, network: systemNetwork{run: runCommand, gateway: subnet.IP.String()}, sockets: &net.ListenConfig{}, shutdownTimeout: 15 * time.Second, done: make(chan struct{}), ready: make(chan struct{})}
	for _, option := range options {
		if err := option(one); err != nil {
			return nil, err
		}
	}
	p, err := NewProxies(cfg.Proxy)
	if err != nil {
		return nil, err
	}
	rule := NewRule(cfg.Rule)
	p.bypassEndpoints(rule)
	one.policy.Store(&runtimeSnapshot{version: 1, cfg: cfg, rule: rule, proxies: p})
	one.dnsTable = NewDnsTable(ip, subnet)
	one.dnsTable.ttl = uint32(cfg.Core.DnsTtl)
	if one.dns, err = NewDns(one, cfg.Core); err != nil {
		return nil, err
	}
	one.tcpRelay = NewTCPRelay(one, cfg.Core)
	one.udpRelay = NewUDPRelay(one, cfg.Core)
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
	cidrs := func(rules []RuleConfig) []RuleConfig {
		var result []RuleConfig
		for _, r := range rules {
			if strings.EqualFold(r.Schema, "IP-CIDR") {
				result = append(result, r)
			}
		}
		return result
	}
	if !reflect.DeepEqual(cfg.Core, old.cfg.Core) || cfg.General != old.cfg.General || !slices.Equal(cidrs(cfg.Rule), cidrs(old.cfg.Rule)) {
		return errors.New("changes to general/core or IP-CIDR routes require restart")
	}
	p, err := NewProxies(cfg.Proxy)
	if err != nil {
		return err
	}
	rule := NewRule(cfg.Rule)
	p.bypassEndpoints(rule)
	one.policy.Store(&runtimeSnapshot{version: old.version + 1, cfg: cfg, rule: rule, proxies: p})
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
	var tcp net.Listener
	var udp, dnsConn net.PacketConn
	var manager net.Listener
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
		for _, c := range []interface{ Close() error }{tcp, udp, manager} {
			if c != nil {
				c.Close()
			}
		}
		one.tcpRelay.active.close()
		one.udpRelay.close()
		if dnsConn != nil {
			dnsConn.Close()
		}
		var cleanup []error
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
		wg.Wait()
		one.tcpRelay.nat.clear()
		one.udpRelay.nat.clear()
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
	if device, err = one.network.Open(ctx, cfg.Core); err != nil {
		return fmt.Errorf("open TUN: %w", err)
	}
	cleanup, err := one.network.Configure(ctx, device, cfg.Core)
	undo.add("interface configuration", cleanup)
	if err != nil {
		return fmt.Errorf("configure TUN: %w", err)
	}
	one.tun = &TunDriver{ifce: device, filters: map[tcpip.IPProtocol]PacketFilter{tcpip.ICMP: PacketFilterFunc(icmpFilterFunc), tcpip.TCP: one.tcpRelay, tcpip.UDP: one.udpRelay}}
	lc := one.sockets
	if tcp, err = lc.Listen(ctx, "tcp4", net.JoinHostPort(one.ip.String(), fmt.Sprint(cfg.Core.TcpListenPort))); err != nil {
		return fmt.Errorf("TCP listener: %w", err)
	}
	if udp, err = lc.ListenPacket(ctx, "udp4", net.JoinHostPort(one.ip.String(), fmt.Sprint(cfg.Core.UdpListenPort))); err != nil {
		return fmt.Errorf("UDP listener: %w", err)
	}
	if dnsConn, err = lc.ListenPacket(ctx, "udp", one.dns.server.Addr); err != nil {
		return fmt.Errorf("DNS listener: %w", err)
	}
	if one.manager != nil {
		if manager, err = lc.Listen(ctx, "tcp", one.manager.listen); err != nil {
			return fmt.Errorf("manager listener: %w", err)
		}
		one.manager.server = &http.Server{Handler: one.manager.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	}
	seen := make(map[string]bool)
	for _, pattern := range one.policy.Load().rule.patterns {
		if p, ok := pattern.(IPCIDRPattern); ok && p.Proxy() != "DIRECT" && !seen[p.ipNet.String()] {
			cleanup, err := one.network.AddRoute(ctx, device, p.ipNet)
			undo.add("route "+p.ipNet.String(), cleanup)
			if err != nil {
				return fmt.Errorf("add route %s: %w", p.ipNet, err)
			}
			seen[p.ipNet.String()] = true
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
	start("TCP relay", func() error { return one.tcpRelay.serve(ctx, tcp) })
	start("UDP relay", func() error { return one.udpRelay.serve(ctx, udp.(*net.UDPConn)) })
	start("DNS cache", func() error { return one.dnsTable.Serve(ctx) })
	start("TUN", func() error { return one.tun.serve(ctx) })
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

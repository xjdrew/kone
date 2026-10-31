package kone

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/xjdrew/kone/pkg/tcpip"
)

type One struct {
	ip     net.IP
	subnet *net.IPNet
	// policyMu coordinates a complete DNS request/flow lookup with reload.
	policyMu sync.RWMutex
	cfg      *KoneConfig
	rule     *Rule
	dnsTable *DnsTable
	proxies  *Proxies
	dns      *Dns
	tcpRelay *TCPRelay
	udpRelay *UDPRelay
	tun      *TunDriver
	manager  *Manager
}

func (one *One) Serve() {
	var wg sync.WaitGroup
	run := func(name string, f func() error) {
		defer wg.Done()
		if err := f(); err != nil {
			slog.Error("Component stopped", "component", name, "error", err)
		}
	}
	components := []struct {
		name  string
		serve func() error
	}{
		{"dns_cache", one.dnsTable.Serve}, {"dns", one.dns.Serve},
		{"tcp_relay", one.tcpRelay.Serve}, {"udp_relay", one.udpRelay.Serve}, {"tun", one.tun.Serve},
	}
	if one.manager != nil {
		components = append(components, struct {
			name  string
			serve func() error
		}{"manager", one.manager.Serve})
	}
	wg.Add(len(components))
	for _, c := range components {
		go run(c.name, c.serve)
	}
	wg.Wait()
}

func cloneConfig(cfg *KoneConfig) *KoneConfig {
	copy := *cfg
	copy.Proxy = maps.Clone(cfg.Proxy)
	copy.Rule = slices.Clone(cfg.Rule)
	copy.Core.DnsServer = slices.Clone(cfg.Core.DnsServer)
	return &copy
}

// Reload accepts rule-only updates. Network, listener, proxy and CIDR changes
// require restart until transactional OS reconfiguration is implemented.
func (one *One) Reload(cfg *KoneConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	one.policyMu.Lock()
	defer one.policyMu.Unlock()
	if one.cfg == nil {
		return errors.New("engine has no active configuration")
	}
	cidrs := func(rules []RuleConfig) []RuleConfig {
		var result []RuleConfig
		for _, r := range rules {
			if strings.EqualFold(r.Schema, "IP-CIDR") {
				result = append(result, r)
			}
		}
		return result
	}
	if !reflect.DeepEqual(cfg.Core, one.cfg.Core) || cfg.General != one.cfg.General || !maps.Equal(cfg.Proxy, one.cfg.Proxy) || !slices.Equal(cidrs(cfg.Rule), cidrs(one.cfg.Rule)) {
		return errors.New("changes to general/core/proxies or IP-CIDR routes require restart")
	}
	rule := NewRule(cfg.Rule)
	one.proxies.bypassEndpoints(rule)
	one.dnsTable.RefreshPolicies(rule)
	one.rule = rule
	one.cfg = cloneConfig(cfg)
	return nil
}

func FromConfig(cfg *KoneConfig) (*One, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cloneConfig(cfg)
	ip, subnet, err := net.ParseCIDR(cfg.Core.Network)
	if err != nil {
		return nil, fmt.Errorf("core.network: %w", err)
	}
	one := &One{ip: ip.To4(), subnet: subnet, cfg: cfg, rule: NewRule(cfg.Rule)}
	if one.proxies, err = NewProxies(cfg.Proxy); err != nil {
		return nil, err
	}
	one.proxies.bypassEndpoints(one.rule)
	one.dnsTable = NewDnsTable(ip, subnet)
	one.dnsTable.ttl = uint32(cfg.Core.DnsTtl)
	if one.dns, err = NewDns(one, cfg.Core); err != nil {
		return nil, err
	}
	one.tcpRelay = NewTCPRelay(one, cfg.Core)
	one.udpRelay = NewUDPRelay(one, cfg.Core)
	filters := map[tcpip.IPProtocol]PacketFilter{tcpip.ICMP: PacketFilterFunc(icmpFilterFunc), tcpip.TCP: one.tcpRelay, tcpip.UDP: one.udpRelay}
	if one.tun, err = NewTunDriver(cfg.Core.Tun, ip, subnet, filters); err != nil {
		return nil, err
	}
	for _, pattern := range one.rule.patterns {
		if p, ok := pattern.(IPCIDRPattern); ok && p.Proxy() != "DIRECT" {
			if err := one.tun.AddRoute(p.ipNet); err != nil {
				one.tun.ifce.Close()
				return nil, fmt.Errorf("add route %s: %w", p.ipNet, err)
			}
		}
	}
	one.manager = NewManager(one, cfg)
	return one, nil
}

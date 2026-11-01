package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
)

// IPv6 capture remains opt-in and is admitted only on platforms with an owned
// address/route implementation and the corresponding native CI acceptance.
func SupportsIPv6Capture() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin"
}

func validateIPv6Platform(cfg CoreConfig) error {
	if cfg.IPv6Network != "" && !SupportsIPv6Capture() {
		return errors.New("IPv6 capture is supported only on Linux, Windows and macOS")
	}
	return nil
}

func (one *One) initIPv6(cfg CoreConfig) {
	if cfg.IPv6Network == "" {
		return
	}
	ip, subnet, _ := net.ParseCIDR(cfg.IPv6Network)
	one.dnsTable6 = NewDnsTable(ip, subnet)
	one.dnsTable6.ipPool.reserve(netip.MustParseAddr(ip.String()).Next())
	if snapshot := one.policy.Load(); snapshot != nil {
		one.dnsTable6.ttl = uint32(snapshot.cfg.DNS.TTL)
	}
}

func (one *One) tableForAddress(address netip.Addr) *DnsTable {
	if address.Is6() && !address.Is4In6() {
		return one.dnsTable6
	}
	return one.dnsTable
}

func (one *One) clearDirectDNSCaches() {
	if one.dnsTable != nil {
		one.dnsTable.ClearNonProxyDomain()
	}
	if one.dnsTable6 != nil {
		one.dnsTable6.ClearNonProxyDomain()
	}
}

func (one *One) domainRecords() map[string]*DomainRecord {
	records := one.dnsTable.Snapshot()
	if one.dnsTable6 != nil {
		for name, record := range one.dnsTable6.Snapshot() {
			records[name+" [AAAA]"] = record
		}
	}
	return records
}

func (one *One) addIPv6Routes(ctx context.Context, device Device, cfg CoreConfig, undo *undoStack) error {
	if cfg.IPv6Network == "" {
		return nil
	}
	var routes []string
	if cfg.AutoRoute6 {
		routes = append(routes, "::/1", "8000::/1")
	}
	snapshot := one.policy.Load()
	for _, pattern := range snapshot.rule.patterns {
		if cidr, ok := pattern.(IPCIDRPattern); ok && cidr.prefix.Addr().Is6() && snapshot.rule.OutboundType(cidr.Proxy()) != OutboundDirect {
			if cidr.prefix.Bits() == 0 {
				routes = append(routes, "::/1", "8000::/1")
			} else {
				routes = append(routes, cidr.prefix.String())
			}
		}
	}
	seen := map[string]bool{}
	for _, route := range routes {
		if seen[route] {
			continue
		}
		seen[route] = true
		_, subnet, _ := net.ParseCIDR(route)
		cleanup, err := one.network.AddRoute(ctx, device, subnet)
		undo.add("IPv6 route "+route, cleanup)
		if err != nil {
			return fmt.Errorf("add IPv6 route %s: %w", route, err)
		}
	}
	return nil
}

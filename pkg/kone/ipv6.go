package kone

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
)

// IPv6 capture is admitted only on platforms with an owned
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

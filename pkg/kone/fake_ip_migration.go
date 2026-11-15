package kone

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// FreshFakeIPNetworks chooses a disjoint generation. It never attempts to infer
// old volatile ownership from a hash. Interface conflicts remain preflighted.
func FreshFakeIPNetworks(cfg *KoneConfig) (string, string, error) {
	excluded := []netip.Prefix{}
	for _, raw := range append([]string{cfg.Core.Network, cfg.Core.IPv6Network}, cfg.DNS.RetiredPools...) {
		if p, err := netip.ParsePrefix(raw); err == nil {
			excluded = append(excluded, p.Masked())
		}
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", "", err
	}
	for _, address := range addresses {
		if p, err := netip.ParsePrefix(address.String()); err == nil {
			excluded = append(excluded, p.Masked())
		}
	}
	free := func(raw string) bool {
		candidate := netip.MustParsePrefix(raw)
		for _, p := range excluded {
			if p.Overlaps(candidate) {
				return false
			}
		}
		return true
	}
	ipv4, ipv6 := "", ""
	for i := 193; i < 256; i++ {
		candidate := fmt.Sprintf("10.%d.0.1/16", i)
		if free(candidate) {
			ipv4 = candidate
			break
		}
	}
	if ipv4 == "" {
		return "", "", errors.New("no disjoint default IPv4 Fake-IP pool is available; choose an unused pool explicitly")
	}
	if cfg.Core.IPv6Network != "" {
		for i := 0; i < 256; i++ {
			candidate := fmt.Sprintf("fd7a:204:%x::1/112", i)
			if free(candidate) {
				ipv6 = candidate
				break
			}
		}
		if ipv6 == "" {
			return "", "", errors.New("no disjoint IPv6 Fake-IP pool is available")
		}
	}
	return ipv4, ipv6, nil
}

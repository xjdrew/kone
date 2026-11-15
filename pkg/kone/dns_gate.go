package kone

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

func validateGateDNSUpstreams(cfg DNSConfig) error {
	if cfg.Mode != "gate" {
		return nil
	}
	listener, err := netip.ParseAddr(cfg.ListenAddress)
	if err != nil {
		return err
	}
	local := map[netip.Addr]bool{listener.Unmap(): true}
	if listener.IsUnspecified() {
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				local[prefix.Addr().Unmap()] = true
			}
		}
	}
	check := func(server string) bool {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return false
		}
		host, port, _ := net.SplitHostPort(normalized)
		address, err := netip.ParseAddr(host)
		return err == nil && port == strconv.Itoa(int(cfg.ListenPort)) && local[address.Unmap()]
	}
	for _, server := range cfg.Servers {
		if check(server) {
			return errors.New("DNS upstream points to KONE's own Gate listener")
		}
	}
	for _, rule := range cfg.Rules {
		if !rule.Unavailable {
			for _, server := range rule.Servers {
				if check(server) {
					return errors.New("split DNS upstream points to KONE's own Gate listener")
				}
			}
		}
	}
	return nil
}

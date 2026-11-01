package kone

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

func validateDNSListenerUpstreams(core CoreConfig, cfg DNSConfig) error {
	self := func(server string) bool {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return false
		}
		host, port, err := net.SplitHostPort(normalized)
		number, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || number != int(cfg.ListenPort) {
			return false
		}
		ip, err := netip.ParseAddr(host)
		ip = ip.Unmap()
		return err == nil && ip.IsLoopback() && (ip.Is4() || core.IPv6Network != "")
	}
	for _, server := range cfg.Servers {
		if self(server) {
			return errors.New("DNS upstream points to KONE's own loopback listener; choose a different upstream address or port")
		}
	}
	for _, rule := range cfg.Rules {
		if rule.Unavailable {
			continue
		}
		for _, server := range rule.Servers {
			if self(server) {
				return errors.New("split DNS upstream points to KONE's own loopback listener; configure that suffix with an independent resolver")
			}
		}
	}
	return nil
}

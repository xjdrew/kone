//go:build !darwin

package kone

func validateDNSListenerUpstreams(_ CoreConfig, cfg DNSConfig) error {
	return validateGateDNSUpstreams(cfg)
}

func configureDNSListenerFamilies(*Dns) {}

//go:build !darwin

package kone

func validateDNSListenerUpstreams(CoreConfig, DNSConfig) error { return nil }

func configureDNSListenerFamilies(*Dns) {}

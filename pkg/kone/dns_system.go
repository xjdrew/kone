package kone

import "context"

// SystemDNSConfigurer guides the host resolver only after every KONE DNS
// listener is ready. Cleanup must run before those listeners are closed.
type SystemDNSConfigurer interface {
	ConfigureSystemDNS(context.Context, Device, CoreConfig, DNSConfig) (Cleanup, error)
}

func (systemNetwork) CheckSystemDNS(ctx context.Context, cfg DNSConfig) error {
	return CheckSystemDNS(ctx, cfg)
}

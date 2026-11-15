package kone

import (
	"context"
	"errors"
)

// ErrSystemDNSUnavailable selects the owned resolver-file adapter on Linux
// hosts that do not use systemd-resolved. Other errors remain fatal.
var ErrSystemDNSUnavailable = errors.New("system DNS integration is unavailable")

// SystemDNSConfigurer guides the host resolver only after every KONE DNS
// listener is ready. Cleanup must run before those listeners are closed.
type SystemDNSConfigurer interface {
	ConfigureSystemDNS(context.Context, Device, CoreConfig, DNSConfig) (Cleanup, error)
}

// SystemDNSLeaseConfigurer reports a lost resolver lease so the engine can stop
// capture rather than continue with silently restored OS DNS. The failure stream
// lasts until cleanup; an unexpected closed stream is also a lease failure.
type SystemDNSLeaseConfigurer interface {
	SystemDNSConfigurer
	ConfigureSystemDNSLease(context.Context, Device, CoreConfig, DNSConfig) (Cleanup, <-chan error, error)
}

func (systemNetwork) CheckSystemDNS(ctx context.Context, cfg DNSConfig) error {
	return CheckSystemDNS(ctx, cfg)
}

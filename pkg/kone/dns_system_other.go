//go:build !linux && !darwin && !windows

package kone

import (
	"context"
	"errors"
)

func SupportsSystemDNS() bool { return false }

func CheckSystemDNS(_ context.Context, cfg DNSConfig) error {
	if cfg.System {
		return errors.New("dns.system is supported on Linux with systemd-resolved, macOS and Windows")
	}
	return nil
}

func (n systemNetwork) ConfigureSystemDNS(ctx context.Context, _ Device, _ CoreConfig, cfg DNSConfig) (Cleanup, error) {
	return nil, CheckSystemDNS(ctx, cfg)
}

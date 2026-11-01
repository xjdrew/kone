//go:build linux || darwin || windows

package kone

import (
	"context"
	"fmt"
	singtun "github.com/sagernet/sing-tun"
	"net"
)

func (n systemNetwork) Open(ctx context.Context, cfg CoreConfig) (Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Tun != "" {
		if _, err := net.InterfaceByName(cfg.Tun); err == nil {
			return nil, fmt.Errorf("refusing to modify existing interface %q", cfg.Tun)
		}
	}
	if err := checkNetworkPrivileges(); err != nil {
		return nil, err
	}
	return openSingDevice(ctx, cfg, func(options singtun.Options) (singtun.Tun, error) {
		return singtun.New(options)
	})
}

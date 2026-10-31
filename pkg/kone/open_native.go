//go:build linux || darwin || windows

package kone

import (
	"context"
	singtun "github.com/sagernet/sing-tun"
)

func (n systemNetwork) Open(ctx context.Context, cfg CoreConfig) (Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkNetworkPrivileges(); err != nil {
		return nil, err
	}
	return openSingDevice(ctx, cfg, func(options singtun.Options) (singtun.Tun, error) {
		return singtun.New(options)
	})
}

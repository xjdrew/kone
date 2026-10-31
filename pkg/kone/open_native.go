//go:build linux || darwin || windows

package kone

import (
	"context"
	singtun "github.com/sagernet/sing-tun"
)

func (n systemNetwork) Open(ctx context.Context, cfg CoreConfig) (Device, error) {
	return openSingDevice(ctx, cfg, func(options singtun.Options) (singtun.Tun, error) {
		return singtun.New(options)
	})
}

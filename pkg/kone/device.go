package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	singtun "github.com/sagernet/sing-tun"
)

type singDevice struct {
	singtun.Tun
	name string
	once sync.Once
	err  error
}

func (d *singDevice) Name() string { return d.name }
func (d *singDevice) Close() error {
	d.once.Do(func() { d.err = d.Tun.Close() })
	return d.err
}

func deviceOptions(cfg CoreConfig) singtun.Options {
	return singtun.Options{Name: cfg.Tun, MTU: MTU, Inet4Address: []netip.Prefix{netip.MustParsePrefix(cfg.Network)},
		// KONE owns network changes and reverse-order rollback. Never let two
		// independent managers configure addresses, DNS or capture routes.
		EXP_ExternalConfiguration: true, EXP_DisableDNSHijack: true, Logger: stackLogger{}}
}

func openSingDevice(ctx context.Context, cfg CoreConfig, create func(singtun.Options) (singtun.Tun, error)) (Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Tun == "" {
		cfg.Tun = singtun.CalculateInterfaceName("kone")
	}
	if _, err := net.InterfaceByName(cfg.Tun); err == nil {
		return nil, fmt.Errorf("refusing to modify existing interface %q", cfg.Tun)
	}
	t, err := create(deviceOptions(cfg))
	if isNilInterface(t) {
		if err == nil {
			err = errors.New("sing-tun returned a nil device")
		}
		return nil, err
	}
	if err != nil {
		return nil, errors.Join(err, t.Close())
	}
	name, err := t.Name()
	if err != nil {
		return nil, errors.Join(err, t.Close())
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, t.Close())
	}
	return &singDevice{Tun: t, name: name}, nil
}

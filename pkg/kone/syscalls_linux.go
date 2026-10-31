package kone

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/songgao/water"
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
	return water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: cfg.Tun}})
}

func (n systemNetwork) Configure(ctx context.Context, d Device, cfg CoreConfig) (Cleanup, error) {
	var undo undoStack
	_, err := n.run(ctx, "ip", "addr", "add", cfg.Network, "dev", d.Name())
	if err != nil {
		return nil, err
	}
	undo.add("address", func(ctx context.Context) error {
		_, err := n.run(ctx, "ip", "addr", "del", cfg.Network, "dev", d.Name())
		return err
	})
	_, err = n.run(ctx, "ip", "link", "set", "dev", d.Name(), "up", "mtu", strconv.Itoa(MTU), "qlen", "1000")
	return undo.restore, err // Closing the exclusively owned device removes the link.
}

func (n systemNetwork) AddRoute(ctx context.Context, d Device, subnet *net.IPNet) (Cleanup, error) {
	_, err := n.run(ctx, "ip", "route", "add", subnet.String(), "dev", d.Name())
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		_, err := n.run(ctx, "ip", "route", "del", subnet.String(), "dev", d.Name())
		return err
	}, nil
}

func fixTunIP(ip net.IP) net.IP { return ip }

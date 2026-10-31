package kone

import (
	"context"

	"net"
	"strconv"
)

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

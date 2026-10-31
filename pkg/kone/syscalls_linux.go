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
	if cfg.IPv6Network != "" {
		_, err = n.run(ctx, "ip", "-6", "addr", "add", cfg.IPv6Network, "dev", d.Name(), "nodad")
		if err != nil {
			return undo.restore, err
		}
		undo.add("IPv6 address", func(ctx context.Context) error {
			_, err := n.run(ctx, "ip", "-6", "addr", "del", cfg.IPv6Network, "dev", d.Name())
			return err
		})
	}
	_, err = n.run(ctx, "ip", "link", "set", "dev", d.Name(), "up", "mtu", strconv.Itoa(MTU), "qlen", "1000")
	return undo.restore, err // Closing the exclusively owned device removes the link.
}

func (n systemNetwork) AddRoute(ctx context.Context, d Device, subnet *net.IPNet) (Cleanup, error) {
	args := []string{"route", "add", subnet.String(), "dev", d.Name()}
	if subnet.IP.To4() == nil {
		args = append([]string{"-6"}, args...)
	}
	_, err := n.run(ctx, "ip", args...)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		copy := append([]string(nil), args...)
		if subnet.IP.To4() == nil {
			copy[2] = "del"
		} else {
			copy[1] = "del"
		}
		_, err := n.run(ctx, "ip", copy...)
		return err
	}, nil
}

func fixTunIP(ip net.IP) net.IP { return ip }

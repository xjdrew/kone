package kone

import (
	"context"

	"net"
	"strconv"
)

func (n systemNetwork) Configure(ctx context.Context, d Device, cfg CoreConfig) (Cleanup, error) {
	if cfg.IPv6Network != "" {
		return n.configureDarwinDualStack(ctx, d, cfg, nativeDarwinAddressOps())
	}
	ip, subnet, _ := net.ParseCIDR(cfg.Network)
	_, err := n.run(ctx, "ifconfig", d.Name(), ip.String(), ip.String(), "mtu", strconv.Itoa(MTU), "netmask", net.IP(subnet.Mask).String(), "up")
	if err != nil {
		return nil, err
	}
	var undo undoStack
	undo.add("interface", func(ctx context.Context) error { _, err := n.run(ctx, "ifconfig", d.Name(), "down"); return err })
	cleanup, err := n.AddRoute(ctx, d, subnet)
	undo.add("virtual subnet", cleanup)
	return undo.restore, err
}

func (n systemNetwork) AddRoute(ctx context.Context, d Device, subnet *net.IPNet) (Cleanup, error) {
	backend := n.routes
	if backend == nil {
		backend = newDarwinRoutes()
	}
	return backend.AddRoute(ctx, d, subnet)
}

func fixTunIP(ip net.IP) net.IP { return net.IPv4zero }

package kone

import (
	"net"
	"net/netip"
)

func (d *Dns) resolverInterface(key, server string) string {
	host, _, _ := net.SplitHostPort(server)
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return "loopback"
	}
	if selected, ok := d.routeClients[key]; ok {
		return selected.device
	}
	if d.one != nil {
		if snapshot := d.one.policy.Load(); snapshot != nil {
			return snapshot.cfg.Core.OutboundInterface
		}
	}
	return ""
}

package kone

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
)

// Each engine owns its dialer. Both proxy transports and DNS must bypass the
// capture routes, including connections established after a rule reload.
func outboundDialer(cfg CoreConfig, dnsServers []string) (*net.Dialer, error) {
	d := &net.Dialer{Timeout: 30 * time.Second}
	if cfg.OutboundInterface == "" {
		return d, nil
	}
	iif, err := net.InterfaceByName(cfg.OutboundInterface)
	if err != nil {
		return nil, fmt.Errorf("outbound interface %q: %w", cfg.OutboundInterface, err)
	}
	if iif.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("outbound interface %q is down", iif.Name)
	}
	d.Control = func(network, address string, conn syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
			// Local proxies and system DNS stubs use the loopback route, which
			// already bypasses capture. Binding them to a physical NIC breaks it.
			return nil
		}
		return control.BindToInterface0(nil, conn, network, address, iif.Name, iif.Index, false)
	}
	// Resolve proxy hostnames through explicit upstreams using the same physical
	// interface. The resolver dialer deliberately has no recursive Resolver.
	resolverDialer := *d
	servers := make([]string, 0, len(dnsServers))
	for _, server := range dnsServers {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return nil, err
		}
		servers = append(servers, normalized)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("DNS servers must be resolved before binding the outbound interface")
	}
	var next atomic.Uint64
	d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		server := servers[(next.Add(1)-1)%uint64(len(servers))]
		return resolverDialer.DialContext(ctx, network, server)
	}}
	return d, nil
}

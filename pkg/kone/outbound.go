package kone

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
)

// Each engine owns its dialer. Both proxy transports and DNS must bypass the
// capture routes, including connections established after a rule reload.
func outboundDialer(cfg CoreConfig) (*net.Dialer, error) {
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
		return control.BindToInterface0(nil, conn, network, address, iif.Name, iif.Index, false)
	}
	// Resolve proxy hostnames through explicit upstreams using the same physical
	// interface. The resolver dialer deliberately has no recursive Resolver.
	resolverDialer := *d
	servers := make([]string, 0, len(cfg.DnsServer))
	for _, server := range cfg.DnsServer {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return nil, err
		}
		servers = append(servers, normalized)
	}
	var next atomic.Uint64
	d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		server := servers[(next.Add(1)-1)%uint64(len(servers))]
		return resolverDialer.DialContext(ctx, network, server)
	}}
	return d, nil
}

package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type ipv6DNSServers struct {
	udp, tcp               *dns.Server
	packet                 net.PacketConn
	listener               net.Listener
	udpStarted, tcpStarted atomic.Bool
}

func (d *Dns) ipv6Servers(cfg DNSConfig) *ipv6DNSServers {
	if d.one.dnsTable6 == nil {
		return nil
	}
	prefix := netip.MustParsePrefix(d.one.policy.Load().cfg.Core.IPv6Network)
	address := net.JoinHostPort(prefix.Addr().String(), strconv.Itoa(int(cfg.ListenPort)))
	if runtime.GOOS == "darwin" {
		// A utun address is a point-to-point endpoint, not a reliable local
		// DNS socket address. Match Darwin's existing loopback IPv4 entry.
		address = net.JoinHostPort("::1", strconv.Itoa(int(cfg.ListenPort)))
	}
	server := func(network string) *dns.Server {
		return &dns.Server{Net: network, Addr: address, Handler: d, UDPSize: int(cfg.PacketSize), ReadTimeout: time.Duration(cfg.ReadTimeout) * time.Second, WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second}
	}
	return &ipv6DNSServers{udp: server("udp6"), tcp: server("tcp6")}
}

func (d *Dns) openIPv6Listeners(ctx context.Context, sockets Sockets) error {
	if d.ipv6 == nil {
		return nil
	}
	var err error
	d.ipv6.packet, err = sockets.ListenPacket(ctx, "udp6", d.ipv6.udp.Addr)
	if err != nil {
		return fmt.Errorf("open IPv6 DNS UDP listener: %w", err)
	}
	listener, err := sockets.Listen(ctx, "tcp6", d.ipv6.tcp.Addr)
	if err != nil {
		return fmt.Errorf("open IPv6 DNS TCP listener: %w", err)
	}
	d.ipv6.listener = &ownedListener{Listener: listener}
	d.ipv6.udp.PacketConn = d.ipv6.packet
	d.ipv6.tcp.Listener = d.ipv6.listener
	return nil
}

func (d *Dns) startIPv6DNS(ctx context.Context, start func(string, func() error), failures <-chan error) error {
	if d.ipv6 == nil {
		return nil
	}
	for _, item := range []struct {
		name    string
		server  *dns.Server
		started *atomic.Bool
	}{{"DNS IPv6 UDP", d.ipv6.udp, &d.ipv6.udpStarted}, {"DNS IPv6 TCP", d.ipv6.tcp, &d.ipv6.tcpStarted}} {
		ready := make(chan struct{})
		item.server.NotifyStartedFunc = func() { item.started.Store(true); close(ready) }
		start(item.name, item.server.ActivateAndServe)
		select {
		case <-ready:
		case err := <-failures:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (d *Dns) stopIPv6DNS(ctx context.Context) error {
	if d.ipv6 == nil {
		return nil
	}
	if d.ipv6.packet != nil {
		d.ipv6.packet.Close()
	}
	var failures []error
	if d.ipv6.listener != nil {
		failures = append(failures, d.ipv6.listener.Close())
	}
	if d.ipv6.udpStarted.Load() {
		failures = append(failures, d.ipv6.udp.ShutdownContext(ctx))
	}
	if d.ipv6.tcpStarted.Load() {
		failures = append(failures, d.ipv6.tcp.ShutdownContext(ctx))
	}
	return errors.Join(failures...)
}

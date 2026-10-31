package kone

import (
	"context"
	"github.com/xjdrew/kone/pkg/tcpip"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

type UDPTunnel struct {
	session    *NatSession
	cliaddr    *net.UDPAddr
	localConn  net.PacketConn
	remoteConn *net.UDPConn
}

func (t *UDPTunnel) Pump() error {
	b := make([]byte, 65535)
	for {
		n, err := t.remoteConn.Read(b)
		if err != nil {
			return err
		}
		if _, err = t.localConn.WriteTo(b[:n], t.cliaddr); err != nil {
			return err
		}
	}
}

type UDPRelay struct {
	one       *One
	nat       *Nat
	relayIP   net.IP
	relayPort uint16
	lock      sync.Mutex
	tunnels   map[string]*UDPTunnel
	closed    bool
	workers   sync.WaitGroup
}

func (r *UDPRelay) grabTunnel(ctx context.Context, s *runtimeSnapshot, local net.PacketConn, client *net.UDPAddr) *UDPTunnel {
	session := r.nat.getSession(uint16(client.Port))
	if session == nil {
		return nil
	}
	key := client.String()
	flow, _ := sessionKey(session.srcIP, session.dstIP, session.srcPort, session.dstPort)
	r.lock.Lock()
	if r.closed {
		r.lock.Unlock()
		return nil
	}
	if tunnel := r.tunnels[key]; tunnel != nil {
		old, _ := sessionKey(tunnel.session.srcIP, tunnel.session.dstIP, tunnel.session.srcPort, tunnel.session.dstPort)
		if old == flow {
			r.lock.Unlock()
			tunnel.remoteConn.SetDeadline(time.Now().Add(NatSessionLifeSeconds * time.Second))
			return tunnel
		}
		delete(r.tunnels, key)
		tunnel.remoteConn.Close()
	}
	r.lock.Unlock()
	record := r.one.dnsTable.GetByIP(session.dstIP)
	if record == nil {
		return nil
	}
	if s.rule.ProxyDNS(record.Hostname, record.resolved) == "REJECT" {
		return nil
	}
	if record.RealIP == nil {
		msg, err := r.one.dns.ResolveContext(ctx, record.Hostname)
		if err != nil {
			return nil
		}
		record.SetRealIP(msg)
		r.one.dnsTable.SetRealIP(record.Hostname, msg)
	}
	if record.RealIP == nil {
		return nil
	}
	addr := (&net.UDPAddr{IP: record.RealIP, Port: int(session.dstPort)}).String()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	if err != nil {
		return nil
	}
	tunnel := &UDPTunnel{session: session, cliaddr: client, localConn: local, remoteConn: conn.(*net.UDPConn)}
	tunnel.remoteConn.SetDeadline(time.Now().Add(NatSessionLifeSeconds * time.Second))
	r.lock.Lock()
	if r.closed {
		r.lock.Unlock()
		conn.Close()
		return nil
	}
	if existing := r.tunnels[key]; existing != nil {
		r.lock.Unlock()
		conn.Close()
		return existing
	}
	r.tunnels[key] = tunnel
	r.workers.Add(1)
	r.lock.Unlock()
	go func() {
		defer r.workers.Done()
		defer conn.Close()
		tunnel.Pump()
		r.lock.Lock()
		if r.tunnels[key] == tunnel {
			delete(r.tunnels, key)
		}
		r.lock.Unlock()
	}()
	return tunnel
}

func (r *UDPRelay) close() {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.closed = true
	for key, tunnel := range r.tunnels {
		tunnel.remoteConn.Close()
		delete(r.tunnels, key)
	}
}
func (r *UDPRelay) serve(parent context.Context, conn net.PacketConn) error {
	ctx, cancel := context.WithCancel(parent)
	defer func() { cancel(); conn.Close(); r.close(); r.workers.Wait() }()
	packet := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(packet)
		if err != nil {
			return err
		}
		client, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		if tunnel := r.grabTunnel(ctx, r.one.policy.Load(), conn, client); tunnel != nil {
			tunnel.remoteConn.Write(packet[:n])
		}
	}
}

// redirect udp packet to relay
func (r *UDPRelay) Filter(wr io.Writer, ipPacket tcpip.IPv4Packet) {
	if err := ipPacket.Validate(); err != nil || ipPacket.Protocol() != tcpip.UDP {
		return
	}
	udpPacket := tcpip.UDPPacket(ipPacket.Payload())

	srcIP := ipPacket.SourceIP()
	dstIP := ipPacket.DestinationIP()
	srcPort := udpPacket.SourcePort()
	dstPort := udpPacket.DestinationPort()

	one := r.one

	if net.IP.Equal(srcIP, r.relayIP) && srcPort == r.relayPort {
		// from remote
		session := r.nat.getSession(dstPort)
		if session == nil {
			slog.Debug("UDP session not found", "src_ip", srcIP, "src_port", srcPort, "dst_ip", dstIP, "dst_port", dstPort)
			return
		}
		ipPacket.SetSourceIP(session.dstIP)
		ipPacket.SetDestinationIP(session.srcIP)
		udpPacket.SetSourcePort(session.dstPort)
		udpPacket.SetDestinationPort(session.srcPort)
	} else if one.dnsTable.Contains(dstIP) {
		// redirect to relay
		isNew, port := r.nat.allocSession(srcIP, dstIP, srcPort, dstPort)
		if port == 0 {
			slog.Warn("UDP NAT table exhausted")
			return
		}

		ipPacket.SetSourceIP(dstIP)
		udpPacket.SetSourcePort(port)
		ipPacket.SetDestinationIP(r.relayIP)
		udpPacket.SetDestinationPort(r.relayPort)

		if isNew {
			slog.Debug("UDP packet redirected", "src_ip", srcIP, "src_port", srcPort, "dst_ip", dstIP, "dst_port", dstPort, "translated_src_ip", dstIP, "translated_src_port", port, "translated_dst_ip", r.relayIP, "translated_dst_port", r.relayPort)
		}
	} else {
		slog.Error("UDP packet rejected", "src_ip", srcIP, "src_port", srcPort, "dst_ip", dstIP, "dst_port", dstPort)
		return
	}

	// write back packet
	udpPacket.ResetChecksum(ipPacket.PseudoSum())
	ipPacket.ResetChecksum()
	wr.Write(ipPacket)
}

func NewUDPRelay(one *One, cfg CoreConfig) *UDPRelay {
	r := new(UDPRelay)
	r.one = one
	r.nat = NewNat(cfg.UdpNatPortStart, cfg.UdpNatPortEnd)
	r.relayIP = one.ip
	r.relayPort = cfg.UdpListenPort
	r.tunnels = make(map[string]*UDPTunnel)
	return r
}

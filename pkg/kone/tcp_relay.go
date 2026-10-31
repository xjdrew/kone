package kone

import (
	"context"
	"github.com/xjdrew/kone/pkg/tcpip"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
)

type TCPRelay struct {
	one       *One
	nat       *Nat
	relayIP   net.IP
	relayPort uint16
	active    connections
}

func (r *TCPRelay) realRemoteHost(conn net.Conn, data *ConnData) (string, string) {
	return r.remoteHost(context.Background(), r.one.policy.Load(), conn, data)
}
func (r *TCPRelay) remoteHost(ctx context.Context, s *runtimeSnapshot, conn net.Conn, data *ConnData) (string, string) {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return "", ""
	}
	session := r.nat.getSession(uint16(remote.Port))
	if session == nil {
		return "", ""
	}
	host := session.dstIP.String()
	policy := s.rule.Proxy(session.dstIP)
	if r.one.dnsTable.IsLocalIP(session.dstIP) {
		record := r.one.dnsTable.GetByIP(session.dstIP)
		if record == nil {
			return "", ""
		}
		host = record.Hostname
		data.Dst = host
		policy = s.rule.ProxyDNS(host, record.resolved)
		if policy == "DIRECT" {
			if record.RealIP == nil {
				msg, err := r.one.dns.ResolveContext(ctx, host)
				if err != nil {
					return "", ""
				}
				record.SetRealIP(msg)
				r.one.dnsTable.SetRealIP(host, msg)
			}
			if record.RealIP == nil {
				return "", ""
			}
			host = record.RealIP.String()
		}
	}
	data.Src = session.srcIP.String()
	if data.Dst == "" {
		data.Dst = host
	}
	data.Proxy = policy
	return net.JoinHostPort(host, strconv.Itoa(int(session.dstPort))), policy
}

type copied struct {
	upload bool
	bytes  int64
}

func relayConnections(left, right net.Conn) (upload, download int64) {
	results := make(chan copied, 2)
	copyDirection := func(dst, src net.Conn, up bool) {
		n, err := io.Copy(dst, src)
		if err != nil {
			left.Close()
			right.Close()
		} else if half, ok := dst.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			dst.Close()
		}
		results <- copied{up, n}
	}
	go copyDirection(right, left, true)
	go copyDirection(left, right, false)
	for range 2 {
		result := <-results
		if result.upload {
			upload = result.bytes
		} else {
			download = result.bytes
		}
	}
	return
}

func (r *TCPRelay) handleConn(ctx context.Context, s *runtimeSnapshot, conn net.Conn) {
	defer func() { conn.Close(); r.active.remove(conn) }()
	var data ConnData
	addr, policy := r.remoteHost(ctx, s, conn, &data)
	if addr == "" {
		return
	}
	tunnel, err := s.proxies.DialContext(ctx, policy, addr)
	if err != nil {
		if ctx.Err() == nil {
			slog.Debug("Proxy dial failed", "destination", addr, "proxy", policy, "error", err)
		}
		return
	}
	if !r.active.add(tunnel) {
		return
	}
	defer func() { tunnel.Close(); r.active.remove(tunnel) }()
	data.Upload, data.Download = relayConnections(conn, tunnel)
	if r.one.manager != nil {
		r.one.manager.Record(data)
	}
}

func (r *TCPRelay) serve(parent context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	defer func() { cancel(); ln.Close(); r.active.close(); wg.Wait() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if !r.active.add(conn) {
			return nil
		}
		s := r.one.policy.Load()
		wg.Add(1)
		go func() { defer wg.Done(); r.handleConn(ctx, s, conn) }()
	}
}

// redirect tcp packet to relay
func (r *TCPRelay) Filter(wr io.Writer, ipPacket tcpip.IPv4Packet) {
	if err := ipPacket.Validate(); err != nil || ipPacket.Protocol() != tcpip.TCP {
		return
	}
	tcpPacket := tcpip.TCPPacket(ipPacket.Payload())

	srcIP := ipPacket.SourceIP()
	dstIP := ipPacket.DestinationIP()
	srcPort := tcpPacket.SourcePort()
	dstPort := tcpPacket.DestinationPort()

	if r.relayIP.Equal(srcIP) && srcPort == r.relayPort {
		// from relay
		session := r.nat.getSession(dstPort)
		if session == nil {
			slog.Debug("TCP session not found", "src_ip", srcIP, "src_port", srcPort, "dst_ip", dstIP, "dst_port", dstPort)
			return
		}

		ipPacket.SetSourceIP(session.dstIP)
		ipPacket.SetDestinationIP(session.srcIP)
		tcpPacket.SetSourcePort(session.dstPort)
		tcpPacket.SetDestinationPort(session.srcPort)
	} else {
		// redirect to relay
		isNew, port := r.nat.allocSession(srcIP, dstIP, srcPort, dstPort)
		if port == 0 {
			slog.Warn("TCP NAT table exhausted")
			return
		}

		ipPacket.SetSourceIP(dstIP)
		tcpPacket.SetSourcePort(port)
		ipPacket.SetDestinationIP(r.relayIP)
		tcpPacket.SetDestinationPort(r.relayPort)

		if isNew {
			slog.Debug("TCP packet redirected", "src_ip", srcIP, "src_port", srcPort, "dst_ip", dstIP, "dst_port", dstPort, "translated_src_ip", dstIP, "translated_src_port", port, "translated_dst_ip", r.relayIP, "translated_dst_port", r.relayPort)
		}
	}

	// write back packet
	tcpPacket.ResetChecksum(ipPacket.PseudoSum())
	ipPacket.ResetChecksum()
	wr.Write(ipPacket)
}

func NewTCPRelay(one *One, cfg CoreConfig) *TCPRelay {
	relay := new(TCPRelay)
	relay.one = one
	relay.nat = NewNat(cfg.TcpNatPortStart, cfg.TcpNatPortEnd)
	relay.relayIP = one.ip
	relay.relayPort = cfg.TcpListenPort
	return relay
}

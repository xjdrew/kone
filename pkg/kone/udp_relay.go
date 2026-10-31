//
//   date  : 2016-05-16
//   author: xjdrew
//

package kone

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/xjdrew/kone/pkg/tcpip"
)

type UDPTunnel struct {
	session *NatSession
	record  *DomainRecord

	cliaddr *net.UDPAddr

	localConn  *net.UDPConn
	remoteConn *net.UDPConn
}

func (tunnel *UDPTunnel) SetDeadline(duration time.Duration) error {
	return tunnel.remoteConn.SetDeadline(time.Now().Add(duration))
}

func (tunnel *UDPTunnel) Pump() error {
	b := make([]byte, MTU)
	for {
		n, err := tunnel.remoteConn.Read(b)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				return nil
			}
			return err
		}
		_, err = tunnel.localConn.WriteToUDP(b[:n], tunnel.cliaddr)
		if err != nil {
			return err
		}
	}
}

func (tunnel *UDPTunnel) Write(b []byte) (int, error) {
	return tunnel.remoteConn.Write(b)
}

type UDPRelay struct {
	one       *One
	nat       *Nat
	relayIP   net.IP
	relayPort uint16

	lock    sync.Mutex
	tunnels map[string]*UDPTunnel
}

// bypass udp packet
func (r *UDPRelay) grabTunnel(localConn *net.UDPConn, cliaddr *net.UDPAddr) *UDPTunnel {
	r.lock.Lock()
	defer r.lock.Unlock()
	addr := cliaddr.String()
	tunnel := r.tunnels[addr]
	if tunnel == nil {
		port := uint16(cliaddr.Port)
		session := r.nat.getSession(port)
		if session == nil {
			return nil
		}
		record := r.one.dnsTable.GetByIP(session.dstIP)
		if record == nil { // by IP-CIDR rule
			return nil
		}
		if record.Proxy == "REJECT" {
			return nil
		}

		if record.RealIP == nil {
			// try resolve real ip
			msg, err := r.one.dns.Resolve(record.Hostname)
			if err == nil {
				record.SetRealIP(msg)
				r.one.dnsTable.SetRealIP(record.Hostname, msg)
			}

			if record.RealIP == nil {
				// resolve real ip failed
				return nil
			}
		}

		srvaddr := &net.UDPAddr{IP: record.RealIP, Port: int(session.dstPort)}
		remoteConn, err := net.DialUDP("udp", nil, srvaddr)
		if err != nil {
			slog.Error("UDP connection failed", "destination", srvaddr, "error", err)
			return nil
		}
		tunnel = &UDPTunnel{
			session:    session,
			record:     record,
			cliaddr:    cliaddr,
			localConn:  localConn,
			remoteConn: remoteConn,
		}

		slog.Debug("UDP tunnel opened", "src_ip", session.srcIP, "src_port", session.srcPort, "destination", srvaddr)

		r.tunnels[addr] = tunnel
		go func() {
			err := tunnel.Pump()
			if err != nil {
				slog.Debug("UDP tunnel read failed", "destination", tunnel.remoteConn.RemoteAddr(), "error", err)
			}
			tunnel.remoteConn.Close()
			slog.Debug("UDP tunnel closed", "src_ip", tunnel.session.srcIP, "src_port", tunnel.session.srcPort, "destination", srvaddr)

			r.lock.Lock()
			delete(r.tunnels, addr)
			r.lock.Unlock()
		}()
	}
	tunnel.SetDeadline(NatSessionLifeSeconds * time.Second)
	return tunnel
}

func (r *UDPRelay) handlePacket(localConn *net.UDPConn, cliaddr *net.UDPAddr, packet []byte) {
	tunnel := r.grabTunnel(localConn, cliaddr)
	if tunnel == nil {
		slog.Error("UDP session not found", "source", cliaddr, "local_address", localConn.LocalAddr())
		return
	}
	_, err := tunnel.Write(packet)
	if err != nil {
		slog.Debug("UDP tunnel write failed", "error", err)
	}
}

func (r *UDPRelay) Serve() error {
	addr := &net.UDPAddr{IP: r.relayIP, Port: int(r.relayPort)}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		slog.Error("UDP listener failed", "error", err)
		return err
	}

	for {
		b := make([]byte, MTU)
		n, cliaddr, err := conn.ReadFromUDP(b)
		if err != nil {
			slog.Error("UDP receive failed", "error", err)
			time.Sleep(time.Second) //prevent log storms
			continue
		}
		go r.handlePacket(conn, cliaddr, b[:n])
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

//
//   date  : 2016-05-16
//   author: xjdrew
//

package k1

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xjdrew/kone/tcpip"
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
		if record == nil || record.realIP == nil {
			return nil
		}
		srvaddr := &net.UDPAddr{IP: record.realIP, Port: int(session.dstPort)}
		remoteConn, err := net.DialUDP("udp", nil, srvaddr)
		if err != nil {
			logger.Errorf("[udp] connect to %s failed: %v", srvaddr, err)
			return nil
		}
		tunnel = &UDPTunnel{
			session:    session,
			record:     record,
			cliaddr:    cliaddr,
			localConn:  localConn,
			remoteConn: remoteConn,
		}

		logger.Debugf("[udp] %s:%d > %v: new tunnel", session.srcIP, session.srcPort, srvaddr)

		r.tunnels[addr] = tunnel
		go func() {
			err := tunnel.Pump()
			if err != nil {
				logger.Debugf("[udp] pump to %v failed: %v", tunnel.remoteConn.RemoteAddr(), err)
			}
			tunnel.remoteConn.Close()
			logger.Debugf("[udp] %s:%d > %v: destroy tunnel", tunnel.session.srcIP, tunnel.session.srcPort, srvaddr)

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
		logger.Errorf("[udp] %v > %v: grap tunnel failed", cliaddr, localConn.LocalAddr())
		return
	}
	_, err := tunnel.Write(packet)
	if err != nil {
		logger.Debugf("[udp] %v", err)
	}
}

func (r *UDPRelay) Serve() error {
	addr := &net.UDPAddr{IP: r.relayIP, Port: int(r.relayPort)}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}

	for {
		b := make([]byte, MTU)
		n, cliaddr, err := conn.ReadFromUDP(b)
		if err != nil {
			return err
		}
		go r.handlePacket(conn, cliaddr, b[:n])
	}
}

// redirect udp packet to relay
func (r *UDPRelay) Filter(wr io.Writer, ipPacket tcpip.IPv4Packet) {
	udpPacket := tcpip.UDPPacket(ipPacket.Payload())

	srcIP := ipPacket.SourceIP()
	dstIP := ipPacket.DestinationIP()
	srcPort := udpPacket.SourcePort()
	dstPort := udpPacket.DestinationPort()

	one := r.one

	if bytes.Equal(srcIP, r.relayIP) && srcPort == r.relayPort {
		// from remote
		session := r.nat.getSession(dstPort)
		if session == nil {
			logger.Errorf("[udp] %s:%d > %s:%d: no session", srcIP, srcPort, dstIP, dstPort)
			return
		}
		ipPacket.SetSourceIP(session.dstIP)
		ipPacket.SetDestinationIP(session.srcIP)
		udpPacket.SetSourcePort(session.dstPort)
		udpPacket.SetDestinationPort(session.srcPort)
	} else if one.subnet.Contains(dstIP) {
		// redirect to relay
		isNew, port := r.nat.allocSession(srcIP, dstIP, srcPort, dstPort)

		ipPacket.SetSourceIP(dstIP)
		udpPacket.SetSourcePort(port)
		ipPacket.SetDestinationIP(r.relayIP)
		udpPacket.SetDestinationPort(r.relayPort)

		if isNew {
			logger.Debugf("[udp] %s:%d > %s:%d: shape to %s:%d > %s:%d",
				srcIP, srcPort, dstIP, dstPort, dstIP, port, r.relayIP, r.relayPort)
		}
	} else {
		logger.Errorf("[udp] %s:%d > %s:%d: invalid packet", srcIP, srcPort, dstIP, dstPort)
		return
	}

	// write back packet
	udpPacket.ResetChecksum(ipPacket.PseudoSum())
	ipPacket.ResetChecksum()
	wr.Write(ipPacket)
}

func NewUDPRelay(one *One, cfg NatConfig) *UDPRelay {
	r := new(UDPRelay)
	r.one = one
	r.nat = NewNat(cfg.NatPortStart, cfg.NatPortEnd)
	r.relayIP = one.ip
	r.relayPort = cfg.ListenPort
	r.tunnels = make(map[string]*UDPTunnel)
	return r
}

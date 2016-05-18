//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/xjdrew/kone/tcpip"
)

type TCPRelay struct {
	one       *One
	nat       *Nat
	relayIP   net.IP
	relayPort uint16
}

func forward(src *net.TCPConn, dst *net.TCPConn) {
	io.Copy(dst, src)

	dst.CloseWrite()
	src.CloseRead()
}

func (r *TCPRelay) realRemoteHost(port uint16) (addr string, proxy string) {
	session := r.nat.getSession(port)
	if session == nil {
		return
	}

	var host string
	if record := r.one.dnsTable.GetByIP(session.dstIP); record != nil {
		host = record.domain
		proxy = record.proxy
	} else {
		host = session.dstIP.String()
	}
	addr = fmt.Sprintf("%s:%d", host, session.dstPort)
	logger.Debugf("[tcp] %s:%d > %s proxy %q", session.srcIP, session.srcPort, addr, proxy)
	return
}

func (r *TCPRelay) handleConn(conn *net.TCPConn) {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	remotePort := uint16(remoteAddr.Port)

	addr, proxy := r.realRemoteHost(remotePort)
	if addr == "" {
		conn.Close()
		logger.Errorf("[tcp] no session: %s", remoteAddr)
		return
	}

	proxies := r.one.proxies
	tunnel, err := proxies.Dial(proxy, addr)
	if err != nil {
		conn.Close()
		logger.Errorf("[tcp] proxy %q failed: %s", proxy, err)
		return
	}

	go forward(tunnel.(*net.TCPConn), conn)
	go forward(conn, tunnel.(*net.TCPConn))
}

func (r *TCPRelay) Serve() error {
	addr := &net.TCPAddr{IP: r.relayIP, Port: int(r.relayPort)}
	ln, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return err
	}

	logger.Infof("[tcp] listen on %v", addr)

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return err
		}
		go r.handleConn(conn)
	}
}

// redirect tcp packet to relay
func (r *TCPRelay) Filter(wr io.Writer, ipPacket tcpip.IPv4Packet) {
	tcpPacket := tcpip.TCPPacket(ipPacket.Payload())

	srcIP := ipPacket.SourceIP()
	dstIP := ipPacket.DestinationIP()
	srcPort := tcpPacket.SourcePort()
	dstPort := tcpPacket.DestinationPort()

	if bytes.Equal(srcIP, r.relayIP) && srcPort == r.relayPort {
		// from relay
		session := r.nat.getSession(dstPort)
		if session == nil {
			logger.Errorf("[tcp] %s:%d > %s:%d: no session", srcIP, srcPort, dstIP, dstPort)
			return
		}

		ipPacket.SetSourceIP(session.dstIP)
		ipPacket.SetDestinationIP(session.srcIP)
		tcpPacket.SetSourcePort(session.dstPort)
		tcpPacket.SetDestinationPort(session.srcPort)
	} else {
		// redirect to relay
		isNew, port := r.nat.allocSession(srcIP, dstIP, srcPort, dstPort)

		ipPacket.SetSourceIP(dstIP)
		tcpPacket.SetSourcePort(port)
		ipPacket.SetDestinationIP(r.relayIP)
		tcpPacket.SetDestinationPort(r.relayPort)

		if isNew {
			logger.Debugf("[tcp] %s:%d > %s:%d: shape to %s:%d > %s:%d",
				srcIP, srcPort, dstIP, dstPort, dstIP, port, r.relayIP, r.relayPort)
		}
	}

	// write back packet
	tcpPacket.ResetChecksum(ipPacket.PseudoSum())
	ipPacket.ResetChecksum()
	wr.Write(ipPacket)
}

func NewTCPRelay(one *One, cfg NatConfig) *TCPRelay {
	relay := new(TCPRelay)
	relay.one = one
	relay.nat = NewNat(cfg.NatPortStart, cfg.NatPortEnd)
	relay.relayIP = one.ip
	relay.relayPort = cfg.ListenPort
	return relay
}

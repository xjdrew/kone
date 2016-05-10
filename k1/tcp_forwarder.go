package k1

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/xjdrew/kone/tcpip"
)

type tcpForwarder struct {
	nat           *Nat
	proxies       *Proxies
	forwarderIP   net.IP
	forwarderPort uint16
}

func forward(src *net.TCPConn, dst *net.TCPConn) {
	io.Copy(dst, src)

	dst.CloseWrite()
	src.CloseRead()
}

func (f *tcpForwarder) handleConn(conn *net.TCPConn) {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	remotePort := uint16(remoteAddr.Port)
	session := f.nat.getSession(remotePort)
	if session == nil {
		conn.Close()
		logger.Debugf("no session: %s", conn.RemoteAddr())
		return
	}

	addr := fmt.Sprintf("%s:%d", session.dstHost, session.dstPort)
	tunnel, err := f.proxies.DefaultDial(addr)
	if err != nil {
		conn.Close()
		logger.Errorf("dial tunnel failed:%s", err)
		return
	}

	go forward(tunnel.(*net.TCPConn), conn)
	go forward(conn, tunnel.(*net.TCPConn))
}

func (f *tcpForwarder) Serve() error {
	addr := &net.TCPAddr{IP: f.forwarderIP, Port: int(f.forwarderPort)}
	ln, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return err
	}

	logger.Infof("listen on: %v", addr)

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return err
		}
		logger.Infof("new connection from %s", conn.RemoteAddr())
		go f.handleConn(conn)
	}
}

// redirect tcp packet to forwarder
func (f *tcpForwarder) Filter(p *tcpip.IPv4Packet) bool {
	ipPacket := *p
	tcpPacket := tcpip.TCPPacket(ipPacket.Payload())

	srcIP := ipPacket.SourceIP()
	dstIP := ipPacket.DestinationIP()
	srcPort := tcpPacket.SourcePort()
	dstPort := tcpPacket.DestinationPort()

	logger.Debugf("tcp: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)

	if bytes.Equal(srcIP, f.forwarderIP) && srcPort == f.forwarderPort {
		// from forwarder
		session := f.nat.getSession(dstPort)
		if session != nil {
			ipPacket.SetSourceIP(session.dstIP)
			tcpPacket.SetSourcePort(session.dstPort)
			ipPacket.SetDestinationIP(session.srcIP)
			tcpPacket.SetDestinationPort(session.srcPort)
		} else {
			logger.Debugf("no session: %s:%d", dstIP, dstPort)
			return false
		}
	} else {
		// redirect to forwarder
		port := f.nat.allocSession(srcIP, dstIP, srcPort, dstPort)

		ipPacket.SetSourceIP(dstIP)
		tcpPacket.SetSourcePort(port)
		ipPacket.SetDestinationIP(f.forwarderIP)
		tcpPacket.SetDestinationPort(f.forwarderPort)

		logger.Debugf("shape from(%s:%d -> %s:%d) to (%s:%d -> %s:%d)",
			srcIP, srcPort, dstIP, dstPort, dstIP, port, f.forwarderIP, f.forwarderPort)
	}

	tcpPacket.ResetChecksum(ipPacket.PseudoSum())
	ipPacket.ResetChecksum()
	p = &ipPacket
	return true
}

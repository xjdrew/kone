package k1

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/xjdrew/kone/tcpip"
)

type TCPForwarder struct {
	one           *One
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

func (f *TCPForwarder) realRemoteHost(port uint16) (addr string, proxy string) {
	session := f.nat.getSession(port)
	if session == nil {
		return
	}

	var host string
	if record := f.one.dnsCache.GetByIP(session.dstIP); record != nil {
		host = record.domain
		proxy = record.proxy
	} else {
		host = session.dstIP.String()
	}
	addr = fmt.Sprintf("%s:%d", host, session.dstPort)
	return
}

func (f *TCPForwarder) handleConn(conn *net.TCPConn) {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	remotePort := uint16(remoteAddr.Port)

	addr, proxy := f.realRemoteHost(remotePort)
	if addr == "" {
		conn.Close()
		logger.Debugf("no session: %s", remoteAddr)
		return
	}

	tunnel, err := f.proxies.Dial(proxy, addr)
	if err != nil {
		conn.Close()
		logger.Errorf("proxy %q failed:%s", proxy, err)
		return
	}

	go forward(tunnel.(*net.TCPConn), conn)
	go forward(conn, tunnel.(*net.TCPConn))
}

func (f *TCPForwarder) Serve() error {
	addr := &net.TCPAddr{IP: f.forwarderIP, Port: int(f.forwarderPort)}
	ln, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return err
	}

	logger.Infof("[tcpForwarder] listen on %v", addr)

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
func (f *TCPForwarder) Filter(p *tcpip.IPv4Packet) bool {
	ipPacket := *p
	tcpPacket := tcpip.TCPPacket(ipPacket.Payload())

	srcIP := ipPacket.SourceIP()
	dstIP := ipPacket.DestinationIP()
	srcPort := tcpPacket.SourcePort()
	dstPort := tcpPacket.DestinationPort()

	// logger.Debugf("tcp: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)

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
		isNew, port := f.nat.allocSession(srcIP, dstIP, srcPort, dstPort)

		ipPacket.SetSourceIP(dstIP)
		tcpPacket.SetSourcePort(port)
		ipPacket.SetDestinationIP(f.forwarderIP)
		tcpPacket.SetDestinationPort(f.forwarderPort)

		if isNew {
			logger.Debugf("shape from(%s:%d -> %s:%d) to (%s:%d -> %s:%d)",
				srcIP, srcPort, dstIP, dstPort, dstIP, port, f.forwarderIP, f.forwarderPort)
		}
	}

	tcpPacket.ResetChecksum(ipPacket.PseudoSum())
	ipPacket.ResetChecksum()
	p = &ipPacket
	return true
}

func NewTCPForwarder(one *One, general GeneralConfig, proxy map[string]*ProxyConfig) (*TCPForwarder, error) {
	proxies, err := NewProxies(proxy)
	if err != nil {
		return nil, err
	}

	forwarder := new(TCPForwarder)
	forwarder.one = one
	forwarder.nat = NewNat(general.NatFromPort, general.NatToPort)
	forwarder.proxies = proxies
	forwarder.forwarderIP = net.ParseIP(general.IP).To4()
	forwarder.forwarderPort = general.ForwarderPort

	return forwarder, nil
}

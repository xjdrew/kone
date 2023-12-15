//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xjdrew/kone/tcpip"
)

type halfCloseConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

type TCPRelay struct {
	one       *One
	nat       *Nat
	relayIP   net.IP
	relayPort uint16
}

func copy(src net.Conn, dst net.Conn, ch chan<- int64) {
	written, _ := io.Copy(dst, src)
	ch <- written
}

func copyAndClose(src halfCloseConn, dst halfCloseConn, ch chan<- int64) {
	written, _ := io.Copy(dst, src)

	dst.CloseWrite()
	src.CloseRead()
	ch <- written
}

func (r *TCPRelay) realRemoteHost(conn net.Conn, connData *ConnData) (addr string, proxy string) {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	remotePort := uint16(remoteAddr.Port)

	session := r.nat.getSession(remotePort)
	if session == nil {
		logger.Errorf("[tcp] %s > %s no session", conn.LocalAddr(), remoteAddr)
		return
	}

	one := r.one

	var host string
	if record := one.dnsTable.GetByIP(session.dstIP); record != nil {
		host = record.Hostname
		proxy = record.Proxy
		logger.Debugf("------------------1")
	} else if one.dnsTable.Contains(session.dstIP) {
		logger.Debugf("[tcp] %s:%d > %s:%d dns expired", session.srcIP, session.srcPort, session.dstIP, session.dstPort)
		return
	} else {
		logger.Debugf("------------------2")
		host = session.dstIP.String()
	}

	connData.Src = session.srcIP.String()
	connData.Dst = host
	connData.Proxy = proxy

	addr = fmt.Sprintf("%s:%d", host, session.dstPort)
	logger.Debugf("[tcp] tunnel %s:%d > %s proxy %q", session.srcIP, session.srcPort, addr, proxy)
	return
}

func (r *TCPRelay) handleConn(conn net.Conn) {
	var connData ConnData
	remoteAddr, proxy := r.realRemoteHost(conn, &connData)
	if remoteAddr == "" {
		conn.Close()
		return
	}

	proxies := r.one.proxies
	tunnel, err := proxies.Dial(proxy, remoteAddr)
	if err != nil {
		conn.Close()
		logger.Errorf("[tcp] dial %s by proxy %q failed: %s", remoteAddr, proxy, err)
		return
	}

	uploadChan := make(chan int64)
	downloadChan := make(chan int64)

	connHCC, connOK := conn.(halfCloseConn)
	tunnelHCC, tunnelOK := tunnel.(halfCloseConn)
	if connOK && tunnelOK {
		go copyAndClose(connHCC, tunnelHCC, uploadChan)
		go copyAndClose(tunnelHCC, connHCC, downloadChan)
	} else {
		go copy(conn, tunnel, uploadChan)
		go copy(tunnel, conn, downloadChan)
		defer conn.Close()
		defer tunnel.Close()
	}
	connData.Upload = <-uploadChan
	connData.Download = <-downloadChan

	if r.one.manager != nil {
		r.one.manager.dataCh <- connData
	}
}

func (r *TCPRelay) Serve() error {
	addr := &net.TCPAddr{IP: r.relayIP, Port: int(r.relayPort)}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	logger.Infof("[tcp] listen on %v", addr)

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			logger.Errorf("acceept failed temporary: %v", err)
			time.Sleep(time.Second) //prevent log storms
			continue
		}
		logger.Debugf("[tcp] new connection [%s > %s]", conn.RemoteAddr(), conn.LocalAddr())
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

	if r.relayIP.Equal(srcIP) && srcPort == r.relayPort {
		// from relay
		session := r.nat.getSession(dstPort)
		if session == nil {
			logger.Debugf("[tcp filter] %s:%d > %s:%d: no session", srcIP, srcPort, dstIP, dstPort)
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
			logger.Debugf("[tcp filter] reshape connection from [%s:%d > %s:%d] to [%s:%d > %s:%d]",
				srcIP, srcPort, dstIP, dstPort, dstIP, port, r.relayIP, r.relayPort)
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

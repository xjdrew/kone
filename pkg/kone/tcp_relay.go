//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/xjdrew/kone/pkg/tcpip"
)

type TCPRelay struct {
	one       *One
	nat       *Nat
	relayIP   net.IP
	relayPort uint16
}

func copy(src net.Conn, dst net.Conn, ch chan<- int64) {
	defer dst.Close()

	written, _ := io.Copy(dst, src)
	ch <- written
}

func (r *TCPRelay) realRemoteHost(conn net.Conn, connData *ConnData) (addr string, proxy string) {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	remotePort := uint16(remoteAddr.Port)

	session := r.nat.getSession(remotePort)
	if session == nil {
		slog.Error("TCP session not found", "local_address", conn.LocalAddr(), "source", remoteAddr)
		return
	}

	one := r.one
	one.policyMu.RLock()
	defer one.policyMu.RUnlock()
	dstIP := session.dstIP

	var host string
	if one.dnsTable.IsLocalIP(dstIP) { // for dns hijacked traffic
		record := one.dnsTable.GetByIP(dstIP)
		if record == nil {
			slog.Debug("Virtual IP mapping expired", "src_ip", session.srcIP, "src_port", session.srcPort, "dst_ip", dstIP, "dst_port", session.dstPort)
			return
		}

		host = record.Hostname
		proxy = record.Proxy
		connData.Dst = host
		if proxy == "DIRECT" {
			if record.RealIP == nil {
				msg, err := one.dns.Resolve(record.Hostname)
				if err != nil {
					return
				}
				record.SetRealIP(msg)
				one.dnsTable.SetRealIP(record.Hostname, msg)
			}
			if record.RealIP == nil {
				return
			}
			host = record.RealIP.String()
		}
	} else { // for IP-CIDR rule traffic
		host = dstIP.String()
		proxy = one.rule.Proxy(dstIP)
	}

	connData.Src = session.srcIP.String()
	if connData.Dst == "" {
		connData.Dst = host
	}
	connData.Proxy = proxy

	addr = net.JoinHostPort(host, strconv.Itoa(int(session.dstPort)))
	slog.Debug("TCP tunnel selected", "src_ip", session.srcIP, "src_port", session.srcPort, "destination", addr, "proxy", proxy)
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
		slog.Error("Proxy dial failed", "destination", remoteAddr, "proxy", proxy, "error", err)
		return
	}

	slog.Debug("TCP tunnel opened", "destination", remoteAddr, "proxy", proxy)

	uploadChan := make(chan int64)
	downloadChan := make(chan int64)

	go copy(conn, tunnel, uploadChan)
	go copy(tunnel, conn, downloadChan)

	connData.Upload = <-uploadChan
	connData.Download = <-downloadChan

	slog.Debug("TCP tunnel closed", "destination", remoteAddr, "upload_bytes", connData.Upload, "download_bytes", connData.Download)
	if r.one.manager != nil {
		r.one.manager.dataCh <- connData
	}
}

func (r *TCPRelay) Serve() error {
	addr := &net.TCPAddr{IP: r.relayIP, Port: int(r.relayPort)}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		slog.Error("TCP listener failed", "error", err)
		return err
	}

	slog.Info("TCP listener starting", "address", addr)

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			slog.Error("TCP accept failed", "error", err)
			time.Sleep(time.Second) //prevent log storms
			continue
		}
		slog.Debug("TCP connection accepted", "source", conn.RemoteAddr(), "local_address", conn.LocalAddr())
		go r.handleConn(conn)
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

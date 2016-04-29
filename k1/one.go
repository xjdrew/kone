package k1

import (
	"fmt"
	"net"

	"github.com/songgao/water"

	. "github.com/xjdrew/kone/internal"
	"github.com/xjdrew/kone/proxy"
	"github.com/xjdrew/kone/tcpip"
)

var logger = GetLogger()

type One struct {
	ip           net.IP
	subnet       *net.IPNet
	tcpForwarder *tcpForwarder
	ifce         *water.Interface
	proxies      map[string]proxy.Dialer
}

func (one *One) init() error {
	ifce, err := newTun("")
	if err != nil {
		return err
	}

	if err = setTunIP(ifce, one.ip, one.subnet); err != nil {
		return err
	}
	one.ifce = ifce

	if one.tcpForwarder, err = newTcpForwarder(one.ip); err != nil {
		return err
	}
	return nil
}

func (one *One) Run() error {
	go one.tcpForwarder.Start()

	buffer := make([]byte, MTU)
	for {
		logger.Debug("read packet")
		n, err := one.ifce.Read(buffer)
		if err != nil {
			return err
		}

		packet := buffer[:n]
		if tcpip.IsIPv4(packet) {
			ipPacket := tcpip.IPv4Packet(packet)
			protocol := ipPacket.Protocol()
			switch protocol {
			case tcpip.ICMP:
				icmpPacket := tcpip.ICMPPacket(ipPacket.Payload())
				if icmpPacket.Type() == tcpip.ICMPRequest && icmpPacket.Code() == 0 {
					logger.Debugf("icmp echo request: %s -> %s", ipPacket.SourceIP(), ipPacket.DestinationIP())

					// forge a reply
					icmpPacket.SetType(tcpip.ICMPEcho)
					srcIP := ipPacket.SourceIP()
					dstIP := ipPacket.DestinationIP()
					ipPacket.SetSourceIP(dstIP)
					ipPacket.SetDestinationIP(srcIP)

					icmpPacket.ResetChecksum()
					ipPacket.ResetChecksum()
					one.ifce.Write(ipPacket)
				} else {
					logger.Debugf("icmp: %s -> %s", ipPacket.SourceIP(), ipPacket.DestinationIP())
				}
				break
			case tcpip.TCP:
				tcpPacket := tcpip.TCPPacket(ipPacket.Payload())
				logger.Debugf("tcp: %s:%d -> %s:%d", ipPacket.SourceIP(), tcpPacket.SourcePort(), ipPacket.DestinationIP(), tcpPacket.DestinationPort())

				// redirect to
				dstIP, dstPort := one.tcpForwarder.GetAddr()
				ipPacket.SetSourceIP(ipPacket.DestinationIP())
				ipPacket.SetDestinationIP(dstIP)
				tcpPacket.SetDestinationPort(dstPort)

				tcpPacket.ResetChecksum(ipPacket.PseudoSum())
				ipPacket.ResetChecksum()
				one.ifce.Write(ipPacket)
				break
			case tcpip.UDP:
				logger.Debugf("udp: %s -> %s", ipPacket.SourceIP(), ipPacket.DestinationIP())
				break
			default:
				logger.Debugf("unsupport protocol: %d", protocol)
			}
		}
	}
}

func NewOne(cfg *KoneConfig) (*One, error) {
	ip := net.ParseIP(cfg.General.IP).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid ipv4 address: %s", cfg.General.IP)
	}

	logger.Debugf("tun ip: %s", ip)

	_, subnet, err := net.ParseCIDR(cfg.General.Subnet)
	if err != nil {
		return nil, err
	}

	logger.Debugf("subnet: %s", subnet)

	if subnet.Contains(ip) {
		return nil, fmt.Errorf("subnet(%s) should not contain tun address(%s)", subnet, ip)
	}

	proxies := make(map[string]proxy.Dialer)
	for name, url := range cfg.Proxy {
		dailer, err := proxy.FromUrl(url)
		if err != nil {
			return nil, err
		}
		proxies[name] = dailer
	}

	one := &One{
		ip:      ip,
		subnet:  subnet,
		proxies: proxies,
	}

	if err = one.init(); err != nil {
		return nil, err
	}
	return one, nil
}

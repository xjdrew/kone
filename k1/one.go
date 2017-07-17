//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"net"

	. "github.com/xjdrew/kone/internal"
	"github.com/xjdrew/kone/tcpip"
)

var logger = GetLogger()

type One struct {
	// tun ip
	ip net.IP

	// tun virtual network
	subnet *net.IPNet

	rule     *Rule
	dnsTable *DnsTable
	proxies  *Proxies

	dns      *Dns
	tcpRelay *TCPRelay
	udpRelay *UDPRelay
	tun      *TunDriver
	manager  *Manager
}

func (one *One) Serve() error {
	done := make(chan error)

	runAndWait := func(f func() error) {
		select {
		case done <- f():
		}
	}

	go runAndWait(one.dnsTable.Serve)
	go runAndWait(one.dns.Serve)
	go runAndWait(one.tcpRelay.Serve)
	go runAndWait(one.udpRelay.Serve)
	go runAndWait(one.tun.Serve)
	if one.manager != nil {
		go runAndWait(one.manager.Serve)
	}
	return <-done
}

func FromConfig(cfg *KoneConfig) (*One, error) {
	general := cfg.General
	ip, subnet, _ := net.ParseCIDR(general.Network)

	logger.Infof("[tun] ip:%s, subnet: %s", ip, subnet)

	one := &One{
		ip:     ip.To4(),
		subnet: subnet,
	}

	// new rule
	one.rule = NewRule(cfg.Rule, cfg.Pattern)

	// new dns cache
	one.dnsTable = NewDnsTable(ip, subnet)

	var err error

	// new dns
	if one.dns, err = NewDns(one, cfg.Dns); err != nil {
		return nil, err
	}

	if one.proxies, err = NewProxies(one, cfg.Proxy); err != nil {
		return nil, err
	}

	one.tcpRelay = NewTCPRelay(one, cfg.TCP)
	one.udpRelay = NewUDPRelay(one, cfg.UDP)

	filters := map[tcpip.IPProtocol]PacketFilter{
		tcpip.ICMP: PacketFilterFunc(icmpFilterFunc),
		tcpip.TCP:  one.tcpRelay,
		tcpip.UDP:  one.udpRelay,
	}

	if one.tun, err = NewTunDriver(ip, subnet, filters); err != nil {
		return nil, err
	}

	one.tun.AddRoutes(cfg.Route.V)

	// new manager
	one.manager = NewManager(one, cfg.Manager)
	return one, nil
}

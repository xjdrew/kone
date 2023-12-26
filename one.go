//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"net"
	"sync"

	"github.com/op/go-logging"
	"github.com/xjdrew/kone/tcpip"
)

var logger = logging.MustGetLogger("kone")

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

func (one *One) Serve() {
	var wg sync.WaitGroup

	runAndWait := func(f func() error) {
		defer wg.Done()
		err := f()
		logger.Errorf("%v", err)
	}

	wg.Add(5)
	go runAndWait(one.dnsTable.Serve)
	go runAndWait(one.dns.Serve)
	go runAndWait(one.tcpRelay.Serve)
	go runAndWait(one.udpRelay.Serve)
	go runAndWait(one.tun.Serve)
	if one.manager != nil {
		wg.Add(1)
		go runAndWait(one.manager.Serve)
	}
	wg.Wait()
}

func (one *One) Reload(cfg *KoneConfig) error {
	one.rule = NewRule(cfg.Rule)
	one.dnsTable.ClearNonProxyDomain()
	return nil
}

func FromConfig(cfg *KoneConfig) (*One, error) {
	ip, subnet, _ := net.ParseCIDR(cfg.Core.Network)

	logger.Infof("[tun] ip:%s, subnet: %s", ip, subnet)

	one := &One{
		ip:     ip.To4(),
		subnet: subnet,
	}

	// new rule
	one.rule = NewRule(cfg.Rule)

	// new dns cache
	one.dnsTable = NewDnsTable(ip, subnet)

	var err error

	// new dns
	if one.dns, err = NewDns(one, cfg.Core); err != nil {
		return nil, err
	}

	if one.proxies, err = NewProxies(one, cfg.Proxy); err != nil {
		return nil, err
	}

	one.tcpRelay = NewTCPRelay(one, cfg.Core)
	one.udpRelay = NewUDPRelay(one, cfg.Core)

	filters := map[tcpip.IPProtocol]PacketFilter{
		tcpip.ICMP: PacketFilterFunc(icmpFilterFunc),
		tcpip.TCP:  one.tcpRelay,
		tcpip.UDP:  one.udpRelay,
	}

	if one.tun, err = NewTunDriver(ip, subnet, filters); err != nil {
		return nil, err
	}

	// set tun as all IP-CIDR rule output
	for _, pattern := range one.rule.patterns {
		switch p := pattern.(type) {
		case IPCIDRPattern:
			one.tun.AddRoute(p.ipNet)
		}
	}

	// new manager
	one.manager = NewManager(one, cfg)
	return one, nil
}

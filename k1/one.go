package k1

import (
	"net"

	. "github.com/xjdrew/kone/internal"
	"github.com/xjdrew/kone/tcpip"
)

var logger = GetLogger()

type One struct {
	rule         *Rule
	dnsCache     *DnsCache
	dns          *Dns
	tcpForwarder *TCPForwarder
	tun          *TunDriver
}

func (one *One) Serve() error {
	done := make(chan error)

	go func() {
		done <- one.dnsCache.Serve()
	}()

	go func() {
		done <- one.dns.Serve()
	}()

	go func() {
		done <- one.tcpForwarder.Serve()
	}()

	go func() {
		done <- one.tun.Serve()
	}()

	return <-done
}

func FromConfig(cfg *KoneConfig) (*One, error) {

	general := cfg.General
	name := general.Tun
	ip := net.ParseIP(general.IP).To4()
	_, subnet, _ := net.ParseCIDR(general.Network)

	logger.Infof("[tun] ip:%s, subnet: %s", ip, subnet)

	one := new(One)
	// new rule
	one.rule = NewRule(cfg.Rule, cfg.Pattern)

	// new dns cache
	one.dnsCache = NewDnsCache(subnet)

	var err error

	// new dns
	if one.dns, err = NewDns(one, cfg.General, cfg.Dns); err != nil {
		return nil, err
	}

	if one.tcpForwarder, err = NewTCPForwarder(one, general, cfg.Proxy); err != nil {
		return nil, err
	}

	filters := map[tcpip.IPProtocol]PacketFilter{
		tcpip.ICMP: PacketFilterFunc(icmpFilterFunc),
		tcpip.TCP:  one.tcpForwarder,
		//tcpip.UDP:  &udpFilter{},
	}

	if one.tun, err = NewTunDriver(name, ip, subnet, filters); err != nil {
		return nil, err
	}

	return one, nil
}

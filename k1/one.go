package k1

import (
	. "github.com/xjdrew/kone/internal"
	"github.com/xjdrew/kone/tcpip"
)

var logger = GetLogger()

type One struct {
	rule         *Rule
	dns          *Dns
	tcpForwarder *TCPForwarder
	tun          *TunDriver
}

func (one *One) Serve() error {
	done := make(chan error)
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

func NewOne(cfg *KoneConfig) (one *One, err error) {
	tcpForwarder, err := NewTCPForwarder(cfg.General, cfg.Proxy)
	if err != nil {
		return
	}

	udpFilter := &udpFilter{}
	filters := map[tcpip.IPProtocol]PacketFilter{
		tcpip.ICMP: PacketFilterFunc(icmpFilterFunc),
		tcpip.TCP:  tcpForwarder,
		tcpip.UDP:  udpFilter,
	}

	tun, err := NewTunDriver(cfg.General, filters)
	if err != nil {
		return
	}

	dns, err := NewDns(cfg.General, cfg.Dns)
	if err != nil {
		return
	}

	one = &One{
		tun:          tun,
		tcpForwarder: tcpForwarder,
		rule:         NewRule(cfg.Rule, cfg.Pattern),
		dns:          dns,
	}
	return
}

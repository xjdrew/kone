package k1

import (
	"fmt"
	"net"

	. "github.com/xjdrew/kone/internal"
	"github.com/xjdrew/kone/tcpip"
)

var logger = GetLogger()

type One struct {
	tun          *TunDriver
	tcpForwarder *tcpForwarder
}

func (one *One) Serve() error {
	done := make(chan error)
	go func() {
		done <- one.tcpForwarder.Serve()
	}()

	go func() {
		done <- one.tun.Serve()
	}()

	return <-done
}

func NewOne(cfg *KoneConfig) (one *One, err error) {
	ip := net.ParseIP(cfg.General.IP).To4()
	if ip == nil {
		err = fmt.Errorf("invalid ipv4 address: %s", cfg.General.IP)
		return
	}

	logger.Debugf("tun ip: %s", ip)

	_, subnet, err := net.ParseCIDR(cfg.General.Network)
	if err != nil {
		return
	}

	logger.Debugf("subnet: %s", subnet)

	if subnet.Contains(ip) {
		err = fmt.Errorf("subnet(%s) should not contain tun address(%s)", subnet, ip)
		return
	}

	proxies, err := newProxyContainer(cfg.Proxies)
	if err != nil {
		return
	}

	tcpForwarder := &tcpForwarder{
		nat:           newNat(cfg.General.NatFromPort, cfg.General.NatToPort),
		proxies:       proxies,
		forwarderIP:   ip,
		forwarderPort: cfg.General.ForwarderPort,
	}
	udpFilter := &udpFilter{}
	filters := map[tcpip.IPProtocol]PacketFilter{
		tcpip.ICMP: PacketFilterFunc(icmpFilterFunc),
		tcpip.TCP:  tcpForwarder,
		tcpip.UDP:  udpFilter,
	}

	tun, err := newTunDriver(cfg.General.Tun, ip, filters)
	if err != nil {
		return
	}

	if err = tun.SetRoute(subnet); err != nil {
		return
	}

	one = &One{
		tun:          tun,
		tcpForwarder: tcpForwarder,
	}
	return
}

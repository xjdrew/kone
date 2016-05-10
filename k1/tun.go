package k1

import (
	"net"

	"github.com/songgao/water"

	"github.com/xjdrew/kone/tcpip"
)

type PacketFilter interface {
	Filter(p *tcpip.IPv4Packet) bool
}

type PacketFilterFunc func(p *tcpip.IPv4Packet) bool

func (f PacketFilterFunc) Filter(p *tcpip.IPv4Packet) bool {
	return f(p)
}

type TunDriver struct {
	ifce    *water.Interface
	filters map[tcpip.IPProtocol]PacketFilter
}

func (tun *TunDriver) Serve() error {
	ifce := tun.ifce
	filters := tun.filters

	buffer := make([]byte, MTU)
	for {
		logger.Debug("read packet")
		n, err := ifce.Read(buffer)
		if err != nil {
			return err
		}

		packet := buffer[:n]
		if tcpip.IsIPv4(packet) {
			ipPacket := tcpip.IPv4Packet(packet)
			protocol := ipPacket.Protocol()
			filter := filters[protocol]
			if filter == nil {
				logger.Debugf("ipv4 protocol: %d", protocol)
				continue
			}

			if filter.Filter(&ipPacket) {
				ifce.Write(ipPacket)
			}
		}
	}
}

func (tun *TunDriver) AddRoute(subnet *net.IPNet) error {
	return addRoute(tun.ifce.Name(), subnet)
}

func NewTunDriver(general GeneralConfig, filters map[tcpip.IPProtocol]PacketFilter) (*TunDriver, error) {
	ifce, err := newTun(general.Tun)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(general.IP).To4()
	logger.Infof("[tun] ip:%s", ip)

	err = setTunIP(ifce, ip)
	if err != nil {
		return nil, err
	}

	_, subnet, _ := net.ParseCIDR(general.Network)
	logger.Infof("[tun] add route:%s", subnet)

	if err = addRoute(ifce.Name(), subnet); err != nil {
		return nil, err
	}
	return &TunDriver{ifce: ifce, filters: filters}, nil
}

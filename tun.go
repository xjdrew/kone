//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"net"

	"github.com/songgao/water"

	"github.com/xjdrew/kone/tcpip"
)

var MTU = 1500

type TunDriver struct {
	ifce    *water.Interface
	filters map[tcpip.IPProtocol]PacketFilter
}

func (tun *TunDriver) Serve() error {
	ifce := tun.ifce
	filters := tun.filters

	buffer := make([]byte, MTU)
	for {
		n, err := ifce.Read(buffer)
		if err != nil {
			logger.Errorf("[tun] read failed: %v", err)
			return err
		}

		packet := buffer[:n]
		if tcpip.IsIPv4(packet) {
			ipPacket := tcpip.IPv4Packet(packet)
			protocol := ipPacket.Protocol()
			filter := filters[protocol]
			if filter == nil {
				logger.Noticef("%v > %v protocol %d unsupport", ipPacket.SourceIP(), ipPacket.DestinationIP(), protocol)
				continue
			}

			filter.Filter(ifce, ipPacket)
		}
	}
}

func (tun *TunDriver) AddRoute(ipNet *net.IPNet) bool {
	addRoute(tun.ifce.Name(), ipNet)
	logger.Infof("add route %s by %s", ipNet.String(), tun.ifce.Name())
	return true
}

func (tun *TunDriver) AddRouteString(val string) bool {
	_, subnet, err := net.ParseCIDR(val)
	if err != nil {
		return false
	}
	return tun.AddRoute(subnet)
}

func NewTunDriver(ip net.IP, subnet *net.IPNet, filters map[tcpip.IPProtocol]PacketFilter) (*TunDriver, error) {
	ifce, err := createTun(ip, subnet.Mask)
	if err != nil {
		return nil, err
	}
	return &TunDriver{ifce: ifce, filters: filters}, nil
}

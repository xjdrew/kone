//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

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

func (tun *TunDriver) AddRoutes(vals []string) {
	name := tun.ifce.Name()
	for _, val := range vals {
		_, subnet, _ := net.ParseCIDR(val)
		if subnet != nil {
			addRoute(name, subnet)
			logger.Infof("add route %s by %s", val, name)
		}
	}
}

func NewTunDriver(ip net.IP, subnet *net.IPNet, filters map[tcpip.IPProtocol]PacketFilter) (*TunDriver, error) {
	ifce, err := createTun(ip, subnet.Mask)
	if err != nil {
		return nil, err
	}
	return &TunDriver{ifce: ifce, filters: filters}, nil
}

//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/xjdrew/kone/pkg/tcpip"
)

var MTU = 1500

type TunDriver struct {
	ifce    tunDevice
	filters map[tcpip.IPProtocol]PacketFilter
}

// tunDevice isolates the packet engine from the current OS driver library.
type tunDevice interface {
	io.ReadWriteCloser
	Name() string
}

func dispatchPacket(w io.Writer, packet []byte, filters map[tcpip.IPProtocol]PacketFilter) error {
	p, err := tcpip.ParseIPv4(packet)
	if err != nil {
		return err
	}
	filter := filters[p.Protocol()]
	if filter == nil {
		return fmt.Errorf("unsupported IP protocol %d", p.Protocol())
	}
	filter.Filter(w, p)
	return nil
}

func (tun *TunDriver) Serve() error {
	ifce := tun.ifce
	filters := tun.filters

	buffer := make([]byte, MTU)
	for {
		n, err := ifce.Read(buffer)
		if err != nil {
			slog.Error("TUN read failed", "error", err)
			return err
		}

		if err := dispatchPacket(ifce, buffer[:n], filters); err != nil {
			slog.Debug("TUN packet dropped", "error", err)
		}
	}
}

func (tun *TunDriver) AddRoute(ipNet *net.IPNet) error {
	if err := addRoute(tun.ifce.Name(), ipNet); err != nil {
		return err
	}
	slog.Info("Route added", "prefix", ipNet.String(), "interface", tun.ifce.Name())
	return nil
}

func (tun *TunDriver) AddRouteString(val string) error {
	_, subnet, err := net.ParseCIDR(val)
	if err != nil {
		return err
	}
	return tun.AddRoute(subnet)
}

func NewTunDriver(name string, ip net.IP, subnet *net.IPNet, filters map[tcpip.IPProtocol]PacketFilter) (*TunDriver, error) {
	ifce, err := createTun(name, ip, subnet.Mask)
	if err != nil {
		return nil, err
	}
	return &TunDriver{ifce: ifce, filters: filters}, nil
}

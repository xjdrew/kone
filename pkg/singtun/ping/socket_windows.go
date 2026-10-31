package ping

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/windows"
)

func connect(privileged bool, controlFunc control.Func, destination netip.Addr) (net.Conn, error) {
	var listenConfig net.ListenConfig
	listenConfig.Control = controlFunc
	if destination.Is6() {
		listenConfig.Control = control.Append(listenConfig.Control, func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_HOPLIMIT, 1)
				if err != nil {
					return err
				}
				return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_RECVTCLASS, 1)
			})
		})
	}
	var network string
	if destination.Is4() {
		network = "ip4:icmp"
	} else {
		network = "ip6:ipv6-icmp"
	}
	// A connected raw socket only receives messages from the connected peer, so transit routers'
	// Time Exceeded replies needed by traceroute never arrive.
	packetConn, err := listenConfig.ListenPacket(context.Background(), network, "")
	if err != nil {
		return nil, err
	}
	return bufio.NewBindPacketConn(packetConn, M.SocksaddrFrom(destination, 0).IPAddr()), nil
}

//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/xjdrew/kone/pkg/tcpip"
)

const MTU = 1500

type TunDriver struct {
	ifce    Device
	filters map[tcpip.IPProtocol]PacketFilter
}

// tunDevice isolates the packet engine from the current OS driver library.

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

func (tun *TunDriver) serve(ctx context.Context) error {
	ifce := tun.ifce
	filters := tun.filters

	buffer := make([]byte, MTU)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := ifce.Read(buffer)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}

		if err := dispatchPacket(ifce, buffer[:n], filters); err != nil {
			slog.Debug("TUN packet dropped", "error", err)
		}
	}
}

//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"io"
	"log/slog"

	"github.com/xjdrew/kone/pkg/tcpip"
)

type PacketFilter interface {
	Filter(wr io.Writer, p tcpip.IPv4Packet)
}

type PacketFilterFunc func(wr io.Writer, p tcpip.IPv4Packet)

func (f PacketFilterFunc) Filter(wr io.Writer, p tcpip.IPv4Packet) {
	f(wr, p)
}

func icmpFilterFunc(wr io.Writer, ipPacket tcpip.IPv4Packet) {
	if err := ipPacket.Validate(); err != nil || ipPacket.Protocol() != tcpip.ICMP {
		return
	}
	icmpPacket := tcpip.ICMPPacket(ipPacket.Payload())
	if icmpPacket.Type() == tcpip.ICMPRequest && icmpPacket.Code() == 0 {
		slog.Debug("ICMP echo request", "src_ip", ipPacket.SourceIP(), "dst_ip", ipPacket.DestinationIP())
		// forge a reply
		icmpPacket.SetType(tcpip.ICMPEcho)
		srcIP := ipPacket.SourceIP()
		dstIP := ipPacket.DestinationIP()
		ipPacket.SetSourceIP(dstIP)
		ipPacket.SetDestinationIP(srcIP)

		icmpPacket.ResetChecksum()
		ipPacket.ResetChecksum()
		wr.Write(ipPacket)
	} else {
		slog.Debug("ICMP packet ignored", "src_ip", ipPacket.SourceIP(), "dst_ip", ipPacket.DestinationIP())
	}
}

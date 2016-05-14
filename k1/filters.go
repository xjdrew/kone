//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"github.com/xjdrew/kone/tcpip"
)

type udpFilter struct {
}

func (uf *udpFilter) Filter(p *tcpip.IPv4Packet) bool {
	return false
}

func icmpFilterFunc(p *tcpip.IPv4Packet) bool {
	ipPacket := *p
	icmpPacket := tcpip.ICMPPacket(ipPacket.Payload())
	if icmpPacket.Type() == tcpip.ICMPRequest && icmpPacket.Code() == 0 {
		logger.Debugf("icmp echo request: %s -> %s", ipPacket.SourceIP(), ipPacket.DestinationIP())
		// forge a reply
		icmpPacket.SetType(tcpip.ICMPEcho)
		srcIP := ipPacket.SourceIP()
		dstIP := ipPacket.DestinationIP()
		ipPacket.SetSourceIP(dstIP)
		ipPacket.SetDestinationIP(srcIP)

		icmpPacket.ResetChecksum()
		ipPacket.ResetChecksum()
		p = &ipPacket
		return true
	} else {
		logger.Debugf("icmp: %s -> %s", ipPacket.SourceIP(), ipPacket.DestinationIP())
		return false
	}
}

package kone

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/tcpip"
)

func TestMalformedPacketNeverReachesFilters(t *testing.T) {
	called := false
	filters := map[tcpip.IPProtocol]PacketFilter{tcpip.TCP: PacketFilterFunc(func(_ io.Writer, p tcpip.IPv4Packet) { called = true })}
	for _, packet := range [][]byte{nil, {}, {0x45}, make([]byte, 19)} {
		var out bytes.Buffer
		require.Error(t, dispatchPacket(&out, packet, filters))
		require.False(t, called)
		require.Empty(t, out.Bytes())
		(&TCPRelay{}).Filter(&out, tcpip.IPv4Packet(packet))
		(&UDPRelay{}).Filter(&out, tcpip.IPv4Packet(packet))
		icmpFilterFunc(&out, tcpip.IPv4Packet(packet))
	}
}

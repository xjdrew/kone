package ping_test

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/rand"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

func TestPing(t *testing.T) {
	t.Parallel()
	const addr4 = "127.0.0.1"
	t.Run("ipv4", func(t *testing.T) {
		t.Run("unprivileged", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.SkipNow()
			}
			t.Run("read-icmp", func(t *testing.T) {
				testPingIPv4ReadICMP(t, false, addr4)
			})
			t.Run("read-ip", func(t *testing.T) {
				testPingIPv4ReadIP(t, false, addr4)
			})
			t.Run("write-ip", func(t *testing.T) {
				testPingIPv4WriteIP(t, false, addr4)
			})
		})
		t.Run("privileged", func(t *testing.T) {
			if runtime.GOOS != "windows" && os.Getuid() != 0 {
				t.SkipNow()
			}
			t.Run("read-icmp", func(t *testing.T) {
				testPingIPv4ReadICMP(t, true, addr4)
			})
			t.Run("read-ip", func(t *testing.T) {
				testPingIPv4ReadIP(t, true, addr4)
			})
			t.Run("write-ip", func(t *testing.T) {
				testPingIPv4WriteIP(t, true, addr4)
			})
		})
	})
	// const addr6 = "2606:4700:4700::1001"
	const addr6 = "::1"
	t.Run("ipv6", func(t *testing.T) {
		t.Run("unprivileged", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.SkipNow()
			}
			t.Run("read-icmp", func(t *testing.T) {
				testPingIPv6ReadICMP(t, false, addr6)
			})
			t.Run("read-ip", func(t *testing.T) {
				testPingIPv6ReadIP(t, false, addr6)
			})
			t.Run("write-ip", func(t *testing.T) {
				testPingIPv6WriteIP(t, false, addr6)
			})
		})
		t.Run("privileged", func(t *testing.T) {
			if runtime.GOOS != "windows" && os.Getuid() != 0 {
				t.SkipNow()
			}
			t.Run("read-icmp", func(t *testing.T) {
				testPingIPv6ReadICMP(t, true, addr6)
			})
			t.Run("read-ip", func(t *testing.T) {
				testPingIPv6ReadIP(t, true, addr6)
			})
			t.Run("write-ip", func(t *testing.T) {
				testPingIPv6WriteIP(t, true, addr6)
			})
		})
	})
}

func testPingIPv4ReadIP(t *testing.T, privileged bool, addr string) {
	conn, err := ping.Connect(context.Background(), privileged, nil, netip.MustParseAddr(addr), 0)
	if runtime.GOOS == "linux" && err != nil && err.Error() == "socket(): permission denied" {
		t.SkipNow()
	}
	require.NoError(t, err)

	request := make(header.ICMPv4, header.ICMPv4MinimumSize)
	request.SetType(header.ICMPv4Echo)
	request.SetIdent(uint16(rand.Uint32()))
	request.SetChecksum(header.ICMPv4Checksum(request, 0))

	err = conn.WriteICMP(buf.As(request).ToOwned())
	require.NoError(t, err)

	conn.SetLocalAddr(netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))

	response := buf.NewPacket()
	err = conn.ReadIP(response)
	require.NoError(t, err)
	if runtime.GOOS == "linux" && privileged {
		response.Reset()
		err = conn.ReadIP(response)
		require.NoError(t, err)
	}
	ipHdr := header.IPv4(response.Bytes())
	require.NotZero(t, ipHdr.TTL())
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	require.Equal(t, header.ICMPv4EchoReply, icmpHdr.Type())
	require.Equal(t, request.Ident(), icmpHdr.Ident())
}

func testPingIPv4ReadICMP(t *testing.T, privileged bool, addr string) {
	conn, err := ping.Connect(context.Background(), privileged, nil, netip.MustParseAddr(addr), 0)
	if runtime.GOOS == "linux" && err != nil && err.Error() == "socket(): permission denied" {
		t.SkipNow()
	}
	require.NoError(t, err)

	request := make(header.ICMPv4, header.ICMPv4MinimumSize)
	request.SetType(header.ICMPv4Echo)
	request.SetIdent(uint16(rand.Uint32()))
	request.SetChecksum(header.ICMPv4Checksum(request, 0))

	err = conn.WriteICMP(buf.As(request).ToOwned())
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))

	response := buf.NewPacket()
	err = conn.ReadICMP(response)
	require.NoError(t, err)

	if runtime.GOOS == "linux" && privileged {
		response.Reset()
		err = conn.ReadICMP(response)
		require.NoError(t, err)
	}

	icmpHdr := header.ICMPv4(response.Bytes())
	require.Equal(t, header.ICMPv4EchoReply, icmpHdr.Type())
	require.Equal(t, request.Ident(), icmpHdr.Ident())
}

func testPingIPv6ReadIP(t *testing.T, privileged bool, addr string) {
	conn, err := ping.Connect(context.Background(), privileged, nil, netip.MustParseAddr(addr), 0)
	if runtime.GOOS == "linux" && err != nil && err.Error() == "socket(): permission denied" {
		t.SkipNow()
	}
	require.NoError(t, err)

	request := make(header.ICMPv6, header.ICMPv6MinimumSize)
	request.SetType(header.ICMPv6EchoRequest)
	request.SetIdent(uint16(rand.Uint32()))

	err = conn.WriteICMP(buf.As(request).ToOwned())
	require.NoError(t, err)

	conn.SetLocalAddr(netip.MustParseAddr("::1"))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))

	response := buf.NewPacket()
	err = conn.ReadIP(response)
	require.NoError(t, err)
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" && privileged {
		response.Reset()
		err = conn.ReadIP(response)
		require.NoError(t, err)
	}
	ipHdr := header.IPv6(response.Bytes())
	require.NotZero(t, ipHdr.HopLimit())
	icmpHdr := header.ICMPv6(ipHdr.Payload())
	require.Equal(t, header.ICMPv6EchoReply, icmpHdr.Type())
	require.Equal(t, request.Ident(), icmpHdr.Ident())
}

func testPingIPv6ReadICMP(t *testing.T, privileged bool, addr string) {
	conn, err := ping.Connect(context.Background(), privileged, nil, netip.MustParseAddr(addr), 0)
	if runtime.GOOS == "linux" && err != nil && err.Error() == "socket(): permission denied" {
		t.SkipNow()
	}
	require.NoError(t, err)

	request := make(header.ICMPv6, header.ICMPv6MinimumSize)
	request.SetType(header.ICMPv6EchoRequest)
	request.SetIdent(uint16(rand.Uint32()))

	err = conn.WriteICMP(buf.As(request).ToOwned())
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))

	response := buf.NewPacket()
	err = conn.ReadICMP(response)
	require.NoError(t, err)
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" && privileged {
		response.Reset()
		err = conn.ReadICMP(response)
		require.NoError(t, err)
	}
	icmpHdr := header.ICMPv6(response.Bytes())
	require.Equal(t, header.ICMPv6EchoReply, icmpHdr.Type())
	require.Equal(t, request.Ident(), icmpHdr.Ident())
}

// testPingIPv4WriteIP exercises the WriteIP send path, which is what the real
// TUN flow uses (Destination.WritePacket -> Conn.WriteIP). Unlike the ReadIP/
// ReadICMP tests, which send via WriteICMP, this path runs the SetTTL call that
// regressed in ebb52fb: on privileged Linux / unprivileged macOS the socket is
// wrapped in a BindPacketConn that does not expose SyscallConn, so
// ipv4.NewConn(c.conn).SetTTL returned "invalid connection" and the echo
// request was never sent.
func testPingIPv4WriteIP(t *testing.T, privileged bool, addr string) {
	conn, err := ping.Connect(context.Background(), privileged, nil, netip.MustParseAddr(addr), 0)
	if runtime.GOOS == "linux" && err != nil && err.Error() == "socket(): permission denied" {
		t.SkipNow()
	}
	require.NoError(t, err)
	defer conn.Close()

	ident := uint16(rand.Uint32())
	const totalLen = header.IPv4MinimumSize + header.ICMPv4MinimumSize
	packet := buf.NewSize(totalLen)
	ipHdr := header.IPv4(packet.Extend(totalLen))
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: totalLen,
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     netip.MustParseAddr("127.0.0.1"),
		DstAddr:     netip.MustParseAddr(addr),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(ident)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	conn.SetLocalAddr(netip.MustParseAddr("127.0.0.1"))
	err = conn.WriteIP(packet)
	require.NoError(t, err, "WriteIP must send the echo request")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	response := buf.NewPacket()
	defer response.Release()
	err = conn.ReadIP(response)
	require.NoError(t, err)
	respIP := header.IPv4(response.Bytes())
	require.NotZero(t, respIP.TTL())
	respICMP := header.ICMPv4(respIP.Payload())
	require.Equal(t, header.ICMPv4EchoReply, respICMP.Type())
	require.Equal(t, ident, respICMP.Ident())
}

func testPingIPv6WriteIP(t *testing.T, privileged bool, addr string) {
	conn, err := ping.Connect(context.Background(), privileged, nil, netip.MustParseAddr(addr), 0)
	if runtime.GOOS == "linux" && err != nil && err.Error() == "socket(): permission denied" {
		t.SkipNow()
	}
	require.NoError(t, err)
	defer conn.Close()

	ident := uint16(rand.Uint32())
	const payloadLen = header.ICMPv6MinimumSize
	packet := buf.NewSize(header.IPv6MinimumSize + payloadLen)
	ipHdr := header.IPv6(packet.Extend(header.IPv6MinimumSize + payloadLen))
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     payloadLen,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           netip.MustParseAddr("::1"),
		DstAddr:           netip.MustParseAddr(addr),
	})
	icmpHdr := header.ICMPv6(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv6EchoRequest)
	icmpHdr.SetIdent(ident)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddressSlice(),
		Dst:    ipHdr.DestinationAddressSlice(),
	}))

	conn.SetLocalAddr(netip.MustParseAddr("::1"))
	err = conn.WriteIP(packet)
	require.NoError(t, err, "WriteIP must send the echo request")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	response := buf.NewPacket()
	defer response.Release()
	err = conn.ReadIP(response)
	require.NoError(t, err)
	if runtime.GOOS == "darwin" {
		response.Reset()
		err = conn.ReadIP(response)
		require.NoError(t, err)
	}
	respIP := header.IPv6(response.Bytes())
	require.NotZero(t, respIP.HopLimit())
	respICMP := header.ICMPv6(respIP.Payload())
	require.Equal(t, header.ICMPv6EchoReply, respICMP.Type())
	require.Equal(t, ident, respICMP.Ident())
}

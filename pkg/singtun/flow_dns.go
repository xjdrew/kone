package tun

import (
	"math"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (d *ForwardDispatcher) hijackDNSPacket(packet *forwardPacket) {
	writer := &dnsResponseWriter{
		writeback: d.writeback,
		source:    packet.source,
	}
	d.handler.NewDNSPacket(header.UDP(packet.transport).Payload(), M.SocksaddrFromNetIP(packet.source), M.SocksaddrFromNetIP(packet.destination), writer)
}

var _ N.PacketWriter = (*dnsResponseWriter)(nil)

type dnsResponseWriter struct {
	writeback ForwardWriteback
	source    netip.AddrPort
}

func (w *dnsResponseWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if !destination.IsIP() {
		return E.New("invalid destination: ", destination)
	}
	sourceAddr := w.source.Addr().Unmap()
	destinationAddr := destination.Addr.Unmap()
	headroom := w.writeback.ReturnHeadroom()
	udpLen := header.UDPMinimumSize + buffer.Len()
	var (
		packet []byte
		udpHdr header.UDP
		ipHdr  header.Network
	)
	if sourceAddr.Is4() {
		if !destinationAddr.Is4() {
			return E.New("send IPv6 packet to IPv4 connection")
		}
		size := header.IPv4MinimumSize + udpLen
		if size > math.MaxUint16 {
			return E.New("DNS response too large: ", buffer.Len())
		}
		packet = make([]byte, headroom+size)
		inet4Hdr := header.IPv4(packet[headroom:])
		inet4Hdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(size),
			TTL:         synthesizedTTL,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     destinationAddr,
			DstAddr:     sourceAddr,
		})
		udpHdr = header.UDP(inet4Hdr.Payload())
		ipHdr = inet4Hdr
	} else {
		if destinationAddr.Is4() {
			destinationAddr = netip.AddrFrom16(destinationAddr.As16())
		}
		if udpLen > math.MaxUint16 {
			return E.New("DNS response too large: ", buffer.Len())
		}
		size := header.IPv6MinimumSize + udpLen
		packet = make([]byte, headroom+size)
		inet6Hdr := header.IPv6(packet[headroom:])
		inet6Hdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpLen),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          synthesizedTTL,
			SrcAddr:           destinationAddr,
			DstAddr:           sourceAddr,
		})
		udpHdr = header.UDP(inet6Hdr.Payload())
		ipHdr = inet6Hdr
	}
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.source.Port(),
		Length:  uint16(udpLen),
	})
	copy(udpHdr.Payload(), buffer.Bytes())
	udpChecksum := ^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), uint16(udpLen)),
	))
	if udpChecksum == 0 {
		udpChecksum = 0xffff
	}
	udpHdr.SetChecksum(udpChecksum)
	if inet4Hdr, isInet4 := ipHdr.(header.IPv4); isInet4 {
		inet4Hdr.SetChecksum(^inet4Hdr.CalculateChecksum())
	}
	return w.writeback.WriteReturnPackets([][]byte{packet})
}

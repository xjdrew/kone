package tun

import (
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

func buildReject(packet *forwardPacket, headroom int) ([]byte, bool) {
	switch packet.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(packet.transport) < header.TCPMinimumSize {
			return nil, false
		}
		tcpHdr := header.TCP(packet.transport)
		switch ipHdr := packet.network.(type) {
		case header.IPv4:
			return buildResetIPv4(ipHdr, tcpHdr, headroom), true
		case header.IPv6:
			return buildResetIPv6(ipHdr, tcpHdr, headroom), true
		default:
			return nil, false
		}
	case uint8(header.UDPProtocolNumber):
		switch ipHdr := packet.network.(type) {
		case header.IPv4:
			return buildRejectICMPv4(ipHdr, header.ICMPv4PortUnreachable, ipHdr.DestinationAddr(), headroom)
		case header.IPv6:
			return buildRejectICMPv6(ipHdr, header.ICMPv6PortUnreachable, ipHdr.DestinationAddr(), headroom)
		default:
			return nil, false
		}
	default:
		switch ipHdr := packet.network.(type) {
		case header.IPv4:
			return buildRejectICMPv4(ipHdr, header.ICMPv4HostUnreachable, ipHdr.DestinationAddr(), headroom)
		case header.IPv6:
			return buildRejectICMPv6(ipHdr, header.ICMPv6AddressUnreachable, ipHdr.DestinationAddr(), headroom)
		default:
			return nil, false
		}
	}
}

func buildResetIPv4(origIPHdr header.IPv4, origTCPHdr header.TCP, headroom int) []byte {
	size := header.IPv4MinimumSize + header.TCPMinimumSize
	buffer := make([]byte, headroom+size)
	ipHdr := header.IPv4(buffer[headroom:])
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         synthesizedTTL,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     origIPHdr.DestinationAddr(),
		DstAddr:     origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	encodeResetTCP(tcpHdr, origTCPHdr)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return buffer
}

func buildResetIPv6(origIPHdr header.IPv6, origTCPHdr header.TCP, headroom int) []byte {
	size := header.IPv6MinimumSize + header.TCPMinimumSize
	buffer := make([]byte, headroom+size)
	ipHdr := header.IPv6(buffer[headroom:])
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          synthesizedTTL,
		SrcAddr:           origIPHdr.DestinationAddr(),
		DstAddr:           origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	encodeResetTCP(tcpHdr, origTCPHdr)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	return buffer
}

func encodeResetTCP(tcpHdr header.TCP, origTCPHdr header.TCP) {
	fields := header.TCPFields{
		SrcPort:    origTCPHdr.DestinationPort(),
		DstPort:    origTCPHdr.SourcePort(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	}
	if origTCPHdr.Flags()&header.TCPFlagAck != 0 {
		fields.SeqNum = origTCPHdr.AckNumber()
	} else {
		fields.Flags |= header.TCPFlagAck
		ackNumber := origTCPHdr.SequenceNumber() + uint32(len(origTCPHdr.Payload()))
		if origTCPHdr.Flags()&header.TCPFlagSyn != 0 {
			ackNumber++
		}
		if origTCPHdr.Flags()&header.TCPFlagFin != 0 {
			ackNumber++
		}
		fields.AckNum = ackNumber
	}
	tcpHdr.Encode(&fields)
}

func buildRejectICMPv4(ipHdr header.IPv4, code header.ICMPv4Code, source netip.Addr, headroom int) ([]byte, bool) {
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	available := maxIPData - header.ICMPv4MinimumSize
	if len(ipHdr) < header.ICMPv4MinimumErrorPayloadSize {
		return nil, false
	}
	payload := []byte(ipHdr)
	if len(payload) > available {
		payload = payload[:available]
	}
	size := header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload)
	buffer := make([]byte, headroom+size)
	newIPHdr := header.IPv4(buffer[headroom:])
	newIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         synthesizedTTL,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     ipHdr.SourceAddr(),
	})
	newIPHdr.SetChecksum(^newIPHdr.CalculateChecksum())
	icmpHdr := header.ICMPv4(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(code)
	copy(icmpHdr.Payload(), payload)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(payload, 0)))
	return buffer, true
}

func buildRejectICMPv6(ipHdr header.IPv6, code header.ICMPv6Code, source netip.Addr, headroom int) ([]byte, bool) {
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	available := maxIPv6Data - header.ICMPv6ErrorHeaderSize
	if available < header.IPv6MinimumSize {
		return nil, false
	}
	payload := []byte(ipHdr)
	if len(payload) > available {
		payload = payload[:available]
	}
	size := header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + len(payload)
	buffer := make([]byte, headroom+size)
	newIPHdr := header.IPv6(buffer[headroom:])
	newIPHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6DstUnreachableMinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          synthesizedTTL,
		SrcAddr:           source,
		DstAddr:           ipHdr.SourceAddr(),
	})
	icmpHdr := header.ICMPv6(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv6DstUnreachable)
	icmpHdr.SetCode(code)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr[:header.ICMPv6DstUnreachableMinimumSize],
		Src:         newIPHdr.SourceAddressSlice(),
		Dst:         newIPHdr.DestinationAddressSlice(),
		PayloadCsum: checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	}))
	copy(icmpHdr.Payload(), payload)
	return buffer, true
}

func BuildUnreachable(packet []byte, source netip.Addr, headroom int) ([]byte, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.FragmentOffset() != 0 {
			return nil, false
		}
		sourceAddr := ipHdr.SourceAddr()
		if sourceAddr.IsUnspecified() || sourceAddr.IsMulticast() {
			return nil, false
		}
		if ipHdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
			if len(ipHdr.Payload()) < header.ICMPv4MinimumSize || header.ICMPv4(ipHdr.Payload()).Type() != header.ICMPv4Echo {
				return nil, false
			}
		}
		replySource := ipHdr.DestinationAddr()
		if source.Is4() {
			replySource = source
		}
		return buildRejectICMPv4(ipHdr, header.ICMPv4HostUnreachable, replySource, headroom)
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) {
			return nil, false
		}
		sourceAddr := ipHdr.SourceAddr()
		if sourceAddr.IsUnspecified() || sourceAddr.IsMulticast() {
			return nil, false
		}
		if ipHdr.TransportProtocol() == header.ICMPv6ProtocolNumber {
			if len(ipHdr.Payload()) < header.ICMPv6MinimumSize || header.ICMPv6(ipHdr.Payload()).Type() != header.ICMPv6EchoRequest {
				return nil, false
			}
		}
		replySource := ipHdr.DestinationAddr()
		if source.Is6() {
			replySource = source
		}
		return buildRejectICMPv6(ipHdr, header.ICMPv6NetworkUnreachable, replySource, headroom)
	default:
		return nil, false
	}
}

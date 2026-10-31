package tun

import (
	"encoding/binary"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type flowKey struct {
	protocol    uint8
	source      netip.AddrPort
	destination netip.AddrPort
}

func (k flowKey) reversed() flowKey {
	return flowKey{protocol: k.protocol, source: k.destination, destination: k.source}
}

type forwardPacket struct {
	ipVersion   uint8
	protocol    uint8
	network     header.Network
	transport   []byte
	source      netip.AddrPort
	destination netip.AddrPort
	tcpFlags    header.TCPFlags
	icmpType    uint8
	fragment    bool
	hasFlow     bool
}

func (p *forwardPacket) flowKey() flowKey {
	return flowKey{protocol: p.protocol, source: p.source, destination: p.destination}
}

func (p *forwardPacket) isTCPSyn() bool {
	return p.protocol == uint8(header.TCPProtocolNumber) && p.tcpFlags&header.TCPFlagSyn != 0
}

func parseForwardPacket(packet []byte) (forwardPacket, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) {
			return forwardPacket{}, false
		}
		parsed := forwardPacket{
			ipVersion:   4,
			protocol:    uint8(ipHdr.TransportProtocol()),
			network:     ipHdr,
			source:      netip.AddrPortFrom(ipHdr.SourceAddr(), 0),
			destination: netip.AddrPortFrom(ipHdr.DestinationAddr(), 0),
		}
		if ipHdr.More() || ipHdr.FragmentOffset() != 0 {
			parsed.fragment = true
			return parsed, true
		}
		parsed.parseTransport(ipHdr.Payload())
		return parsed, true
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) {
			return forwardPacket{}, false
		}
		protocol, payload, fragment, transportPresent := skipIPv6ExtensionHeaders(uint8(ipHdr.TransportProtocol()), ipHdr.Payload())
		parsed := forwardPacket{
			ipVersion:   6,
			protocol:    protocol,
			network:     ipHdr,
			source:      netip.AddrPortFrom(ipHdr.SourceAddr(), 0),
			destination: netip.AddrPortFrom(ipHdr.DestinationAddr(), 0),
			fragment:    fragment,
		}
		if fragment || !transportPresent {
			return parsed, true
		}
		parsed.parseTransport(payload)
		return parsed, true
	default:
		return forwardPacket{}, false
	}
}

func skipIPv6ExtensionHeaders(protocol uint8, payload []byte) (uint8, []byte, bool, bool) {
	for {
		switch header.IPv6ExtensionHeaderIdentifier(protocol) {
		case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier:
			if len(payload) < 2 {
				return protocol, payload, false, false
			}
			extensionLength := (int(payload[1]) + 1) * 8
			if len(payload) < extensionLength {
				return protocol, payload, false, false
			}
			protocol = payload[0]
			payload = payload[extensionLength:]
		case header.IPv6FragmentExtHdrIdentifier:
			return protocol, payload, true, false
		default:
			return protocol, payload, false, true
		}
	}
}

func (p *forwardPacket) parseTransport(payload []byte) {
	p.transport = payload
	switch p.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(payload) < header.TCPMinimumSize {
			return
		}
		tcpHdr := header.TCP(payload)
		tcpHeaderLength := int(tcpHdr.DataOffset())
		if tcpHeaderLength < header.TCPMinimumSize || tcpHeaderLength > len(payload) {
			return
		}
		p.source = netip.AddrPortFrom(p.source.Addr(), tcpHdr.SourcePort())
		p.destination = netip.AddrPortFrom(p.destination.Addr(), tcpHdr.DestinationPort())
		p.tcpFlags = tcpHdr.Flags()
		p.hasFlow = true
	case uint8(header.UDPProtocolNumber):
		if len(payload) < header.UDPMinimumSize {
			return
		}
		udpHdr := header.UDP(payload)
		p.source = netip.AddrPortFrom(p.source.Addr(), udpHdr.SourcePort())
		p.destination = netip.AddrPortFrom(p.destination.Addr(), udpHdr.DestinationPort())
		p.hasFlow = true
	case uint8(header.ICMPv4ProtocolNumber):
		if len(payload) < header.ICMPv4MinimumSize {
			return
		}
		icmpHdr := header.ICMPv4(payload)
		p.icmpType = uint8(icmpHdr.Type())
		switch icmpHdr.Type() {
		case header.ICMPv4Echo, header.ICMPv4EchoReply:
			identifier := icmpHdr.Ident()
			p.source = netip.AddrPortFrom(p.source.Addr(), identifier)
			p.destination = netip.AddrPortFrom(p.destination.Addr(), identifier)
			p.hasFlow = true
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(payload) < header.ICMPv6MinimumSize {
			return
		}
		icmpHdr := header.ICMPv6(payload)
		p.icmpType = uint8(icmpHdr.Type())
		switch icmpHdr.Type() {
		case header.ICMPv6EchoRequest, header.ICMPv6EchoReply:
			identifier := icmpHdr.Ident()
			p.source = netip.AddrPortFrom(p.source.Addr(), identifier)
			p.destination = netip.AddrPortFrom(p.destination.Addr(), identifier)
			p.hasFlow = true
		}
	}
}

func (p *forwardPacket) isICMPError() bool {
	switch p.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		switch header.ICMPv4Type(p.icmpType) {
		case header.ICMPv4DstUnreachable, header.ICMPv4SrcQuench, header.ICMPv4Redirect, header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
			return true
		}
		return false
	case uint8(header.ICMPv6ProtocolNumber):
		return header.ICMPv6Type(p.icmpType).IsErrorType()
	default:
		return false
	}
}

func (p *forwardPacket) icmpErrorInner() ([]byte, bool) {
	var innerOffset int
	switch p.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		innerOffset = header.ICMPv4MinimumSize
	case uint8(header.ICMPv6ProtocolNumber):
		innerOffset = header.ICMPv6ErrorHeaderSize
	default:
		return nil, false
	}
	if len(p.transport) <= innerOffset {
		return nil, false
	}
	return p.transport[innerOffset:], true
}

type embeddedPacket struct {
	network     header.Network
	payload     []byte
	protocol    uint8
	source      netip.AddrPort
	destination netip.AddrPort
}

func (p *embeddedPacket) flowKey() flowKey {
	return flowKey{protocol: p.protocol, source: p.source, destination: p.destination}
}

func parseEmbedded(inner []byte) (embeddedPacket, bool) {
	switch header.IPVersion(inner) {
	case header.IPv4Version:
		if len(inner) < header.IPv4MinimumSize {
			return embeddedPacket{}, false
		}
		ipHdr := header.IPv4(inner)
		headerLength := int(ipHdr.HeaderLength())
		if headerLength < header.IPv4MinimumSize || headerLength > len(inner) {
			return embeddedPacket{}, false
		}
		return parseEmbeddedTransport(ipHdr, inner[headerLength:], uint8(ipHdr.TransportProtocol()), ipHdr.SourceAddr(), ipHdr.DestinationAddr())
	case header.IPv6Version:
		if len(inner) < header.IPv6MinimumSize {
			return embeddedPacket{}, false
		}
		ipHdr := header.IPv6(inner)
		protocol, payload, _, transportPresent := skipIPv6ExtensionHeaders(uint8(ipHdr.TransportProtocol()), inner[header.IPv6MinimumSize:])
		if !transportPresent {
			return embeddedPacket{}, false
		}
		return parseEmbeddedTransport(ipHdr, payload, protocol, ipHdr.SourceAddr(), ipHdr.DestinationAddr())
	default:
		return embeddedPacket{}, false
	}
}

func parseEmbeddedTransport(network header.Network, payload []byte, protocol uint8, source, destination netip.Addr) (embeddedPacket, bool) {
	embedded := embeddedPacket{
		network:  network,
		payload:  payload,
		protocol: protocol,
	}
	switch protocol {
	case uint8(header.TCPProtocolNumber), uint8(header.UDPProtocolNumber):
		if len(payload) < 4 {
			return embeddedPacket{}, false
		}
		embedded.source = netip.AddrPortFrom(source, binary.BigEndian.Uint16(payload[0:]))
		embedded.destination = netip.AddrPortFrom(destination, binary.BigEndian.Uint16(payload[2:]))
	case uint8(header.ICMPv4ProtocolNumber):
		if len(payload) < header.ICMPv4MinimumSize {
			return embeddedPacket{}, false
		}
		identifier := header.ICMPv4(payload).Ident()
		embedded.source = netip.AddrPortFrom(source, identifier)
		embedded.destination = netip.AddrPortFrom(destination, identifier)
	case uint8(header.ICMPv6ProtocolNumber):
		if len(payload) < header.ICMPv6MinimumSize {
			return embeddedPacket{}, false
		}
		identifier := header.ICMPv6(payload).Ident()
		embedded.source = netip.AddrPortFrom(source, identifier)
		embedded.destination = netip.AddrPortFrom(destination, identifier)
	default:
		return embeddedPacket{}, false
	}
	return embedded, true
}

package tun

import (
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
)

// segmentRetainCount bounds how many segment buffers survive a Flush; the pool
// grows to the burst high-water mark within a batch and is trimmed afterwards.
const segmentRetainCount = 128

// Linux delivers TSO aggregates to the TUN even with IFF_VNET_HDR off
// (observed on 6.x: the pre-segmentation skb is handed to the fd as-is).
func (d *ForwardDispatcher) resegmentTCP(flow *forwardFlow, packet *forwardPacket, raw []byte) {
	if len(packet.transport) < header.TCPMinimumSize {
		return
	}
	headerLength := len(raw) - len(packet.transport)
	if packet.ipVersion == 6 && headerLength != header.IPv6MinimumSize {
		reply, ok := buildPacketTooBig(packet.network.(header.IPv6), flow.effectiveMTU, d.writeback.ReturnHeadroom())
		if ok {
			d.writebackBatch = append(d.writebackBatch, reply)
		}
		return
	}
	tcpHeaderLength := int(header.TCP(packet.transport).DataOffset())
	if tcpHeaderLength < header.TCPMinimumSize || tcpHeaderLength > len(packet.transport) {
		return
	}
	totalHeaderLength := headerLength + tcpHeaderLength
	segmentSize := int(flow.effectiveMTU) - totalHeaderLength
	if segmentSize <= 0 {
		return
	}
	gsoType := GSOTCPv4
	if packet.ipVersion == 6 {
		gsoType = GSOTCPv6
	}
	neededSegments := max((len(raw)-totalHeaderLength+segmentSize-1)/segmentSize, 1)
	bufs, sizes := d.reserveSegments(neededSegments, int(flow.effectiveMTU))
	n, err := GSOSplit(raw, GSOOptions{
		GSOType:    gsoType,
		HdrLen:     uint16(totalHeaderLength),
		CsumStart:  uint16(headerLength),
		CsumOffset: header.TCPChecksumOffset,
		GSOSize:    uint16(segmentSize),
	}, bufs, sizes, 0)
	if err != nil {
		d.logger.Trace(E.Cause(err, "resegment packet"))
		return
	}
	for i := range n {
		d.stagePort(flow.nat, bufs[i][:sizes[i]])
	}
}

func (d *ForwardDispatcher) reserveSegments(count, size int) ([][]byte, []int) {
	start := d.segmentUsed
	end := start + count
	for len(d.segmentBuffers) < end {
		d.segmentBuffers = append(d.segmentBuffers, make([]byte, size))
		d.segmentSizes = append(d.segmentSizes, 0)
	}
	for i := start; i < end; i++ {
		if cap(d.segmentBuffers[i]) < size {
			d.segmentBuffers[i] = make([]byte, size)
		} else {
			d.segmentBuffers[i] = d.segmentBuffers[i][:size]
		}
	}
	d.segmentUsed = end
	return d.segmentBuffers[start:end], d.segmentSizes[start:end]
}

const synthesizedTTL = 64

func fragmentIPv4Packet(packet header.IPv4, effectiveMTU uint32) ([][]byte, bool) {
	headerLength := int(packet.HeaderLength())
	if headerLength < header.IPv4MinimumSize || headerLength >= len(packet) {
		return nil, false
	}
	payload := packet[headerLength:]
	maxFragmentPayload := (int(effectiveMTU) - headerLength) &^ 7
	if maxFragmentPayload <= 0 {
		return nil, false
	}
	baseOffset := packet.FragmentOffset()
	originalMore := packet.Flags()&header.IPv4FlagMoreFragments != 0
	baseFlags := packet.Flags() &^ header.IPv4FlagMoreFragments
	fragments := make([][]byte, 0, (len(payload)+maxFragmentPayload-1)/maxFragmentPayload)
	for start := 0; start < len(payload); start += maxFragmentPayload {
		end := min(start+maxFragmentPayload, len(payload))
		fragment := header.IPv4(make([]byte, headerLength+end-start))
		copy(fragment, packet[:headerLength])
		copy(fragment[headerLength:], payload[start:end])
		flags := baseFlags
		if originalMore || end < len(payload) {
			flags |= header.IPv4FlagMoreFragments
		}
		fragment.SetFlagsFragmentOffset(flags, baseOffset+uint16(start))
		fragment.SetTotalLength(uint16(len(fragment)))
		fragment.SetChecksum(0)
		fragment.SetChecksum(^fragment.CalculateChecksum())
		fragments = append(fragments, fragment)
	}
	return fragments, true
}

func buildFragmentationNeeded(packet header.IPv4, effectiveMTU uint32, headroom int) ([]byte, bool) {
	advertised := max(effectiveMTU, header.IPv4MinimumMTU)
	originalLength := min(int(packet.TotalLength()), len(packet))
	minPayloadLength := int(packet.HeaderLength()) + header.ICMPv4MinimumErrorPayloadSize
	if originalLength < minPayloadLength {
		return nil, false
	}
	maxPayloadLength := header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize - header.ICMPv4MinimumSize
	payloadLength := min(originalLength, maxPayloadLength)
	size := header.IPv4MinimumSize + header.ICMPv4MinimumSize + payloadLength
	buffer := make([]byte, headroom+size)
	response := header.IPv4(buffer[headroom:])
	response.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         synthesizedTTL,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     packet.DestinationAddr(),
		DstAddr:     packet.SourceAddr(),
	})
	response.SetChecksum(^response.CalculateChecksum())
	icmpHdr := header.ICMPv4(response.Payload())
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(header.ICMPv4FragmentationNeeded)
	icmpHdr.SetMTU(uint16(min(advertised, uint32(0xffff))))
	copy(icmpHdr.Payload(), packet[:payloadLength])
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	return buffer, true
}

func buildPacketTooBig(packet header.IPv6, effectiveMTU uint32, headroom int) ([]byte, bool) {
	advertised := max(effectiveMTU, header.IPv6MinimumMTU)
	originalLength := min(header.IPv6MinimumSize+int(packet.PayloadLength()), len(packet))
	if originalLength < header.IPv6MinimumSize {
		return nil, false
	}
	maxPayloadLength := header.IPv6MinimumMTU - header.IPv6MinimumSize - header.ICMPv6PacketTooBigMinimumSize
	payloadLength := min(originalLength, maxPayloadLength)
	size := header.IPv6MinimumSize + header.ICMPv6PacketTooBigMinimumSize + payloadLength
	buffer := make([]byte, headroom+size)
	response := header.IPv6(buffer[headroom:])
	response.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6PacketTooBigMinimumSize + payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          synthesizedTTL,
		SrcAddr:           packet.DestinationAddr(),
		DstAddr:           packet.SourceAddr(),
	})
	icmpHdr := header.ICMPv6(response.Payload())
	icmpHdr.SetType(header.ICMPv6PacketTooBig)
	icmpHdr.SetCode(header.ICMPv6UnusedCode)
	icmpHdr.SetMTU(advertised)
	copy(icmpHdr.Payload(), packet[:payloadLength])
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    response.SourceAddressSlice(),
		Dst:    response.DestinationAddressSlice(),
	}))
	return buffer, true
}

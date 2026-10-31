//
//   date  : 2016-05-13
//   author: xjdrew
//

package tcpip

import (
	"encoding/binary"
	"errors"
	"net"
)

type IPProtocol byte

const (
	ICMP IPProtocol = 0x01
	TCP  IPProtocol = 0x06
	UDP  IPProtocol = 0x11
)

type IPv4Packet []byte

// ParseIPv4 validates lengths before any zero-copy header view is accessed.
// Fragment reassembly is not implemented; reject all fragments explicitly.
func ParseIPv4(packet []byte) (IPv4Packet, error) {
	p := IPv4Packet(packet)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p[:p.TotalLen()], nil
}

func (p IPv4Packet) Validate() error {
	if len(p) < 20 || !IsIPv4(p) {
		return errors.New("truncated or non-IPv4 packet")
	}
	header, total := int(p.HeaderLen()), int(p.TotalLen())
	if header < 20 || header > total || total > len(p) {
		return errors.New("invalid IPv4 lengths")
	}
	if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return errors.New("IPv4 fragments are unsupported")
	}
	payload := p[header:total]
	switch p.Protocol() {
	case TCP:
		if len(payload) < 20 {
			return errors.New("truncated TCP header")
		}
		offset := int(payload[12]>>4) * 4
		if offset < 20 || offset > len(payload) {
			return errors.New("invalid TCP data offset")
		}
	case UDP:
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return errors.New("invalid UDP length")
		}
	case ICMP:
		if len(payload) < 8 {
			return errors.New("truncated ICMP header")
		}
	}
	return nil
}

func (p IPv4Packet) TotalLen() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p IPv4Packet) HeaderLen() uint16 {
	return uint16(p[0]&0xf) * 4
}

func (p IPv4Packet) DataLen() uint16 {
	return p.TotalLen() - p.HeaderLen()
}

func (p IPv4Packet) Payload() []byte {
	return p[p.HeaderLen():p.TotalLen()]
}

func (p IPv4Packet) Protocol() IPProtocol {
	return IPProtocol(p[9])
}

func (p IPv4Packet) SourceIP() net.IP {
	var ip = [4]byte{p[12], p[13], p[14], p[15]}
	return net.IP(ip[:])
}

func (p IPv4Packet) SetSourceIP(ip net.IP) {
	ip = ip.To4()
	if ip != nil {
		copy(p[12:16], ip)
	}
}

func (p IPv4Packet) DestinationIP() net.IP {
	var ip = [4]byte{p[16], p[17], p[18], p[19]}
	return net.IP(ip[:])
}

func (p IPv4Packet) SetDestinationIP(ip net.IP) {
	ip = ip.To4()
	if ip != nil {
		copy(p[16:20], ip)
	}
}

func (p IPv4Packet) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[10:])
}

func (p IPv4Packet) SetChecksum(sum [2]byte) {
	p[10] = sum[0]
	p[11] = sum[1]
}

func (p IPv4Packet) ResetChecksum() {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(0, p[:p.HeaderLen()]))
}

// for tcp checksum
func (p IPv4Packet) PseudoSum() uint32 {
	sum := Sum(p[12:20])
	sum += uint32(p.Protocol())
	sum += uint32(p.DataLen())
	return sum
}

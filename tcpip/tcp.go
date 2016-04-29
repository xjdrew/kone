package tcpip

import (
	"encoding/binary"
)

type TCPPacket []byte

func (p TCPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p TCPPacket) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(p, port)
}

func (p TCPPacket) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p TCPPacket) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(p[2:], port)
}

func (p TCPPacket) SetChecksum(sum [2]byte) {
	p[16] = sum[0]
	p[17] = sum[1]
}

func (p TCPPacket) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[16:])
}

func (p TCPPacket) ResetChecksum(psum uint32) {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(psum, p))
}

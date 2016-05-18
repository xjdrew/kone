//
//   date  : 2016-05-17
//   author: xjdrew
//

package tcpip

import (
	"encoding/binary"
)

type UDPPacket []byte

func (p UDPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p UDPPacket) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(p, port)
}

func (p UDPPacket) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p UDPPacket) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(p[2:], port)
}

func (p UDPPacket) SetChecksum(sum [2]byte) {
	p[6] = sum[0]
	p[7] = sum[1]
}

func (p UDPPacket) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[6:])
}

func (p UDPPacket) ResetChecksum(psum uint32) {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(psum, p))
}

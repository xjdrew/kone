//
//   date  : 2016-05-13
//   author: xjdrew
//

package tcpip

import (
	"encoding/binary"
)

type ICMPType byte

const (
	ICMPEcho    ICMPType = 0x0
	ICMPRequest          = 0x8
)

type ICMPPacket []byte

func (p ICMPPacket) Type() ICMPType {
	return ICMPType(p[0])
}

func (p ICMPPacket) SetType(v ICMPType) {
	p[0] = byte(v)
}

func (p ICMPPacket) Code() byte {
	return p[1]
}

func (p ICMPPacket) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p ICMPPacket) SetChecksum(sum [2]byte) {
	p[2] = sum[0]
	p[3] = sum[1]
}

func (p ICMPPacket) ResetChecksum() {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(0, p))
}

//
//   date  : 2016-05-13
//   author: xjdrew
//

package tcpip

import (
	"net"
)

func IsIPv4(packet []byte) bool {
	return (packet[0] >> 4) == 4
}

func IsIPv6(packet []byte) bool {
	return (packet[0] >> 4) == 6
}

func ConvertIPv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}

	v := uint32(ip[0]) << 24
	v += uint32(ip[1]) << 16
	v += uint32(ip[2]) << 8
	v += uint32(ip[3])
	return v
}

func ConvertUint32ToIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

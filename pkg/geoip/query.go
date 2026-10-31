//
//   date  : 2016-05-13
//   author: xjdrew
//

package geoip

import (
	"net"
	"net/netip"
)

func QueryCountry(ip uint32) string {
	return Builtin().Country(netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}))
}

func QueryCountryByIP(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}

	v := uint32(ip[0]) << 24
	v += uint32(ip[1]) << 16
	v += uint32(ip[2]) << 8
	v += uint32(ip[3])
	return QueryCountry(v)
}

func QueryCountryByString(v string) string {
	ip := net.ParseIP(v)
	if ip == nil {
		return ""
	}
	return QueryCountryByIP(ip)
}

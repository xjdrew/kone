//
//   date  : 2016-05-13
//   author: xjdrew
//

package geoip

import (
	"net"
	"sort"
)

var (
	geoIPLen = len(geoIP)
)

func QueryCountry(ip uint32) string {
	i := sort.Search(geoIPLen, func(i int) bool {
		n := geoIP[i]
		return n.End >= ip
	})

	var country string
	if i < geoIPLen {
		n := geoIP[i]
		if n.Start <= ip {
			country = n.Name
		}
	}
	return country
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

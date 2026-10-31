package geoip

import (
	"net"
	"testing"
)

var cases = map[string]string{
	"1.208.0.0":       "KR",
	"114.114.114.114": "CN",
	"101.226.103.106": "CN",
	"14.17.32.211":    "CN",
	"8.8.8.8":         "US",
	"183.79.227.111":  "JP",
	"255.255.255.255": "",
	"192.168.0.1":     "",
	"224.0.0.1":       "",
}

func TestQuery(t *testing.T) {
	for ip, country := range cases {
		result := QueryCountryByString(ip)
		if country != result {
			t.Errorf("failed on: %s:%s ! %s", ip, country, result)
		}
	}

	for v, country := range cases {
		ip := net.ParseIP(v)
		result := QueryCountryByIP(ip)
		if country != result {
			t.Errorf("failed on: %s:%s ! %s", ip, country, result)
		}
	}
}

func BenchmarkQuery(b *testing.B) {
	var i uint32 = 1
	for ; i < 1000000; i++ {
		QueryCountry(i)
	}
}

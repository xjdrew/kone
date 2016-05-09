package k1

import (
	"net"
	"testing"

	"github.com/xjdrew/kone/tcpip"
)

func checkCases(t *testing.T, proxy string, pattern Pattern, cases map[interface{}]bool) {
	if proxy != pattern.Proxy() {
		t.Fatalf("proxy failed, proxy: %s, expected: %s", pattern.Proxy(), proxy)
	}

	for c, expected := range cases {
		if pattern.Match(c) != expected {
			t.Fatalf("match failed, proxy: %s, case: %v", pattern.Proxy(), c)
		}
	}
}

func TestDomainSuffixPattern(t *testing.T) {
	proxy := "A"
	pattern := NewDomainSuffixPattern(proxy, []string{
		"example.com",
		"hk",
	})

	cases := map[interface{}]bool{
		"example.com":     true,
		"api.example.com": true,
		"1example.com":    false,
		"example.hk":      true,
		"example.1hk":     false,
	}
	checkCases(t, proxy, pattern, cases)
}

func TestDomainKeywordPattern(t *testing.T) {
	proxy := "B"
	pattern := NewDomainKeywordPattern(proxy, []string{
		"example.com",
		"hk",
	})

	cases := map[interface{}]bool{
		"hk.com":          true,
		"example.com":     true,
		"api.example.com": true,
		"1example.com":    true,
		"example.hk":      true,
		"example.1hk":     true,
		"xample.com":      false,
	}
	checkCases(t, proxy, pattern, cases)
}

func TestIPCountryPattern(t *testing.T) {
	proxy := "C"
	pattern := NewIPCountryPattern(proxy, []string{
		"HK",
		"US",
	})

	cases := map[interface{}]bool{
		tcpip.ConvertIPv4ToUint32(net.ParseIP("216.58.197.99")): true, // google.hk
		tcpip.ConvertIPv4ToUint32(net.ParseIP("8.8.8.8")):       true, // google us dns
		"8.8.8.8": false, // must be a net.IP or uint32 for IPCountryPattern
		tcpip.ConvertIPv4ToUint32(net.ParseIP("114.114.114.114")): false, // china dns
	}
	checkCases(t, proxy, pattern, cases)
}

func TestIPCIDRPattern(t *testing.T) {
	proxy := "D"
	pattern := NewIPCIDRPattern(proxy, []string{
		"192.168.100.1/16",
		"10.18.0.1/24",
		"172.16.0.1/32",
	})

	cases := map[interface{}]bool{
		tcpip.ConvertIPv4ToUint32(net.ParseIP("192.167.255.255")): false,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("192.168.0.0")):     true,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("192.168.255.255")): true,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("10.17.0.0")):       false,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("10.18.0.0")):       true,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("10.18.0.255")):     true,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("172.16.0.0")):      false,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("172.16.0.1")):      true,
		tcpip.ConvertIPv4ToUint32(net.ParseIP("172.16.0.2")):      false,
		"172.16.0.1": false, // must be a net.IP or uint32 for IPCountryPattern
	}
	checkCases(t, proxy, pattern, cases)
}

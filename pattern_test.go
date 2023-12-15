//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"net"
	"testing"

	"github.com/xjdrew/kone/tcpip"

	"github.com/stretchr/testify/assert"
)

func TestDomainPattern(t *testing.T) {
	pattern := NewDomainPattern("A", "Example.com")
	assert.Equal(t, "A", pattern.Proxy())
	assert.True(t, pattern.Match("example.com"))
	assert.True(t, pattern.Match("Example.Com"))      // case insensitive
	assert.False(t, pattern.Match("api.example.com")) // suffix
	assert.False(t, pattern.Match("1example.com"))
	assert.False(t, pattern.Match("example.hk"))
	assert.False(t, pattern.Match("example.com.hk"))
}

func TestDomainSuffixPattern(t *testing.T) {
	pattern := NewDomainSuffixPattern("A", "Example.com")
	assert.Equal(t, "A", pattern.Proxy())
	assert.True(t, pattern.Match("example.com"))
	assert.True(t, pattern.Match("Example.Com"))     // case insensitive
	assert.True(t, pattern.Match("api.example.com")) // suffix
	assert.True(t, pattern.Match("1example.com"))
	assert.False(t, pattern.Match("example.hk"))
	assert.False(t, pattern.Match("example.com.hk"))
}

func TestDomainKeywordPattern(t *testing.T) {
	pattern := NewDomainKeywordPattern("A", "Example.com")
	assert.Equal(t, "A", pattern.Proxy())
	assert.True(t, pattern.Match("example.com"))
	assert.True(t, pattern.Match("Example.Com"))     // case insensitive
	assert.True(t, pattern.Match("api.example.com")) // suffix
	assert.True(t, pattern.Match("1example.com"))
	assert.False(t, pattern.Match("example.hk"))
	assert.True(t, pattern.Match("example.com.hk"))
}

func TestIPCountryPattern(t *testing.T) {
	pattern := NewGEOIPPattern("A", "US")
	assert.Equal(t, "A", pattern.Proxy())
	assert.True(t, pattern.Match(net.ParseIP("216.58.197.99")))  // google.hk
	assert.False(t, pattern.Match(net.ParseIP("110.242.68.66"))) // baidu.com, china
}

func TestIPCIDRPattern(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.100.1/16")
	pattern := NewIPCIDRPattern("D", ipNet)
	assert.Equal(t, "D", pattern.Proxy())
	assert.False(t, pattern.Match(net.ParseIP("192.167.255.255")))
	assert.True(t, pattern.Match(net.ParseIP("192.168.0.0")))
	assert.True(t, pattern.Match(net.ParseIP("192.168.255.255")))
	assert.True(t, pattern.Match(net.ParseIP("192.168.108.255")))
	assert.False(t, pattern.Match(tcpip.ConvertIPv4ToUint32(net.ParseIP("192.167.255.255"))))
	assert.True(t, pattern.Match(tcpip.ConvertIPv4ToUint32(net.ParseIP("192.168.0.0"))))
	assert.True(t, pattern.Match(tcpip.ConvertIPv4ToUint32(net.ParseIP("192.168.255.255"))))
	assert.True(t, pattern.Match(tcpip.ConvertIPv4ToUint32(net.ParseIP("192.168.108.255"))))
}

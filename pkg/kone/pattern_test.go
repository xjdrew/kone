//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"net"
	"testing"

	"net/netip"

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
	assert.True(t, pattern.Match("API.EXAMPLE.COM."))
	assert.False(t, pattern.Match("1example.com"))
	assert.False(t, pattern.Match("example.hk"))
	assert.False(t, pattern.Match("example.com.hk"))
}

func TestDirectCIDRRuleKeepsItsPriority(t *testing.T) {
	rule := NewRule([]RuleConfig{{Schema: "IP-CIDR", Pattern: "10.1.0.0/16", Outbound: BuiltinDirect}, {Schema: "IP-CIDR", Pattern: "10.0.0.0/8", Outbound: "A"}}, []OutboundConfig{{Name: "A"}})
	assert.Equal(t, "direct", rule.Proxy(net.ParseIP("10.1.2.3")))
	assert.Equal(t, "A", rule.Proxy(net.ParseIP("10.2.2.3")))
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
	assert.True(t, pattern.Match(netip.MustParseAddr("216.58.197.99")))
	assert.False(t, pattern.Match(netip.MustParseAddr("2001:db8::1")))
}

func TestIPCIDRPattern(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.100.1/16")
	pattern := NewIPCIDRPattern("D", prefix)
	assert.Equal(t, "D", pattern.Proxy())
	assert.False(t, pattern.Match(net.ParseIP("192.167.255.255")))
	assert.True(t, pattern.Match(net.ParseIP("192.168.0.0")))
	assert.True(t, pattern.Match(net.ParseIP("192.168.255.255")))
	assert.True(t, pattern.Match(net.ParseIP("192.168.108.255")))
	assert.False(t, pattern.Match(netip.MustParseAddr("192.167.255.255")))
	assert.True(t, pattern.Match(netip.MustParseAddr("192.168.0.0")))
	assert.True(t, pattern.Match(netip.MustParseAddr("192.168.255.255")))
	assert.True(t, pattern.Match(netip.MustParseAddr("192.168.108.255")))
	assert.True(t, pattern.Match(netip.MustParseAddr("::ffff:192.168.108.255")))
	assert.False(t, pattern.Match(netip.MustParseAddr("2001:db8::1")))
	assert.False(t, pattern.Match(netip.Addr{}))
}

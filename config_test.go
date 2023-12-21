//
//   date  : 2023-12-13
//   author: xjdrew
//

package kone

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	confData = `
	[General]
	manager-addr = "0.0.0.0:9200"

	[Core]
	network = 10.192.0.1/16

	tcp-listen-port = 82
	tcp-nat-port-start = 10000
	tcp-nat-port-end = 60000

	udp-listen-port = 82
	udp-nat-port-start = 10000
	udp-nat-port-end = 60000

	dns-listen-port = 53
	dns-ttl = 600
	dns-packet-size = 4096
	dns-read-timeout = 5
	dns-write-timeout = 5
	dns-server = 1.1.1.1,8.8.8.8

	[Proxy]
	# define a http proxy named "Proxy1"
	Proxy1 = http://proxy.example.com:8080

	# define a socks5 proxy named "Proxy2"
	Proxy2 = socks5://127.0.0.1:9080

	[Rule]
	IP-CIDR, 91.108.4.0/22, Proxy1 # rule 0
	IP-CIDR,91.108.56.0/22,Proxy1 # rule 1
	IP-CIDR,109.239.140.0/24,Proxy1
	IP-CIDR,149.154.167.0/24,Proxy1
	IP-CIDR,172.16.0.0/16,DIRECT
	IP-CIDR,192.168.0.0/16,DIRECT

	IP-CIDR6,2001:db8:abcd:8000::/50,DIRECT

	# match if the domain 
	DOMAIN, www.twitter.com, Proxy1
	DOMAIN-SUFFIX,twitter.com,Proxy1
	DOMAIN-SUFFIX,telegram.org,Proxy1
	DOMAIN-KEYWORD,google,Proxy1
	DOMAIN-KEYWORD,localhost,DIRECT
	DOMAIN-KEYWORD,baidu,REJECT

	# match if the GeoIP test result matches a specified country code
	GEOIP,US,DIRECT # rule 13

	# define default policy for requests which are not matched by any other rules
	FINAL,DIRECT # rule 14
	`
)

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte(confData))

	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "0.0.0.0:9200", cfg.General.ManagerAddr)

	assert.Equal(t, "10.192.0.1/16", cfg.Core.Network)

	assert.Equal(t, uint16(82), cfg.Core.TcpListenPort)
	assert.Equal(t, uint16(10000), cfg.Core.TcpNatPortStart)
	assert.Equal(t, uint16(60000), cfg.Core.TcpNatPortEnd)

	assert.Equal(t, uint16(82), cfg.Core.UdpListenPort)
	assert.Equal(t, uint16(10000), cfg.Core.UdpNatPortStart)
	assert.Equal(t, uint16(60000), cfg.Core.UdpNatPortEnd)

	assert.Equal(t, uint16(53), cfg.Core.DnsListenPort)
	assert.Equal(t, uint(600), cfg.Core.DnsTtl)
	assert.Equal(t, uint16(4096), cfg.Core.DnsPacketSize)
	assert.Equal(t, uint(5), cfg.Core.DnsReadTimeout)
	assert.Equal(t, uint(5), cfg.Core.DnsWriteTimeout)
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, cfg.Core.DnsServer)

	assert.Equal(t, "http://proxy.example.com:8080", cfg.Proxy["Proxy1"])
	assert.Equal(t, "socks5://127.0.0.1:9080", cfg.Proxy["Proxy2"])

	assert.Len(t, cfg.Rule, 15)
	assert.Equal(t, cfg.Rule[0].Schema, "IP-CIDR")
	assert.Equal(t, cfg.Rule[0].Pattern, "91.108.4.0/22")
	assert.Equal(t, cfg.Rule[0].Proxy, "Proxy1")

	assert.Equal(t, cfg.Rule[1].Schema, "IP-CIDR")
	assert.Equal(t, cfg.Rule[1].Pattern, "91.108.56.0/22")
	assert.Equal(t, cfg.Rule[1].Proxy, "Proxy1")

	assert.Equal(t, cfg.Rule[14].Schema, "FINAL")
	assert.Equal(t, cfg.Rule[14].Pattern, "")
	assert.Equal(t, cfg.Rule[14].Proxy, "DIRECT")
}

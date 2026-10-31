package kone

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSRecordSnapshotsAndTTL(t *testing.T) {
	ip, subnet, _ := net.ParseCIDR("10.192.0.1/24")
	table := NewDnsTable(ip, subnet)
	table.ttl = 42
	r := table.Set("example.com", "A")
	require.Equal(t, uint32(42), r.answer.Hdr.Ttl)
	require.WithinDuration(t, time.Now().Add(42*time.Second), r.Expires, time.Second)
	r.Proxy = "B"
	r.IP[0] = 0
	require.Equal(t, "A", table.Get("example.com").Proxy)
	snapshot := table.Snapshot()
	snapshot["example.com"].Proxy = "C"
	require.Equal(t, "A", table.Get("example.com").Proxy)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	answer := table.Get("example.com").Answer(request)
	answer.Answer[0].(*dns.A).A[0] = 0
	require.Equal(t, byte(10), table.Get("example.com").answer.A[0])
}

func TestDNSPoolExhaustionReturnsNil(t *testing.T) {
	ip, subnet, _ := net.ParseCIDR("10.192.0.1/30")
	table := NewDnsTable(ip, subnet)
	require.NotNil(t, table.Set("a.example", "A"))
	require.Nil(t, table.Set("b.example", "A"))
}

func TestNonProxyExpiryCheckedOnRead(t *testing.T) {
	ip, subnet, _ := net.ParseCIDR("10.192.0.1/24")
	table := NewDnsTable(ip, subnet)
	table.SetNonProxyDomain("example.com", 0)
	require.False(t, table.IsNonProxyDomain("example.com"))
}

package kone

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSCacheTTLNegativeAndCapacity(t *testing.T) {
	cache := newDNSResponseCache(1)
	request := new(dns.Msg)
	request.SetQuestion("a.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.IPv4(192, 0, 2, 1)}}
	now := time.Now()
	key := dnsCacheKey(request, "")
	cache.put(key, response, now)
	response.Answer[0].Header().Ttl = 1
	hit := cache.get(key, 42, now.Add(2*time.Second))
	require.Equal(t, uint16(42), hit.Id)
	require.Equal(t, uint32(8), hit.Answer[0].Header().Ttl)
	hit.Answer[0].Header().Ttl = 99
	require.Equal(t, uint32(7), cache.get(key, 43, now.Add(3*time.Second)).Answer[0].Header().Ttl)
	require.Nil(t, cache.get(key, 44, now.Add(10*time.Second)))
	negative := new(dns.Msg)
	negative.SetRcode(request, dns.RcodeNameError)
	negative.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 5}}
	require.Equal(t, uint32(5), cacheTTL(negative))
	negative.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "missing.example."}}
	require.Equal(t, uint32(5), cacheTTL(negative), "CNAME does not replace the negative SOA TTL")
	withoutSOA := negative.Copy()
	withoutSOA.Ns = nil
	require.Zero(t, cacheTTL(withoutSOA), "NXDOMAIN with a CNAME still needs an SOA to be cached")
	cache.put(key, negative, now)
	require.Equal(t, dns.RcodeNameError, cache.get(key, request.Id, now).Rcode)
	other := request.Copy()
	other.SetQuestion("b.example.", dns.TypeA)
	cache.put(dnsCacheKey(other, ""), negative, now.Add(time.Second))
	require.Nil(t, cache.get(key, request.Id, now.Add(time.Second)))
	cache.prune(now.Add(10 * time.Second))
	require.Empty(t, cache.entries)
	request.SetEdns0(4096, true)
	require.Empty(t, dnsCacheKey(request, ""))
	request.Extra = nil
	request.CheckingDisabled = true
	require.Empty(t, dnsCacheKey(request, ""))
	negative.Truncated = true
	require.Zero(t, cacheTTL(negative))
	newDNSResponseCache(0).put("a", negative, now)
}

func TestDNSHistoryRetentionCapacityAndClear(t *testing.T) {
	history := newDNSHistory(2, time.Second)
	now := time.Now()
	for _, name := range []string{"a", "b", "c"} {
		history.add(DNSQueryEvent{Time: now, Name: name, RealAddresses: []string{"192.0.2.1"}})
	}
	entries := history.snapshot(now)
	require.Len(t, entries, 2)
	require.Equal(t, "c", entries[0].Name)
	require.Equal(t, uint64(1), history.dropped)
	entries[0].RealAddresses[0] = "mutated"
	require.Equal(t, "192.0.2.1", history.snapshot(now)[0].RealAddresses[0])
	require.Empty(t, history.snapshot(now.Add(2*time.Second)))
	history.add(DNSQueryEvent{Time: now.Add(2 * time.Second), Name: "d"})
	history.clear()
	require.Empty(t, history.snapshot(now.Add(2*time.Second)))
	require.Zero(t, history.dropped)
	newDNSHistory(0, time.Second).add(DNSQueryEvent{})
}

func TestFakeIPPinPreventsRecycle(t *testing.T) {
	address, subnet, _ := net.ParseCIDR("192.0.2.1/30")
	table := NewDnsTable(address, subnet)
	record := table.Set("active.example", "office")
	require.NotNil(t, record)
	release := table.Pin(record.Hostname)
	table.records[record.Hostname].Expires = time.Now().Add(-time.Second)
	table.clearExpiredDomain(time.Now())
	require.NotNil(t, table.Get(record.Hostname))
	release()
	release()
	table.records[record.Hostname].Expires = time.Now().Add(-time.Second)
	table.clearExpiredDomain(time.Now())
	require.Nil(t, table.Get(record.Hostname))
	table.Pin("missing")()
}

func TestDNSMaintenanceCancelsWithoutNetworkChanges(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, one.dns.Maintain(ctx))
	var empty *One
	require.Empty(t, empty.DNSQueries())
	empty.ClearDNSQueries()
	empty.ClearDNSCache()
	require.Empty(t, empty.DNSStatus().Servers)
}

package kone

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSSnapshotDropsExpiredRealEvidenceWithoutTouchingMapping(t *testing.T) {
	var queries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) { queries.Add(1); replyA(w, request, "192.0.2.9") })
	upstream := startDNSListeners(t, handler, handler)
	one := dnsEngine(t, upstream)
	cfg := one.Snapshot().Config
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "192.0.2.0/24", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}
	snapshot := *one.policy.Load()
	snapshot.rule = NewRule(cfg.Rule, cfg.Outbounds)
	one.policy.Store(&snapshot)
	record := one.dnsTable.Set("cached.example", "office")
	one.dnsTable.SetRealIP(record.Hostname, &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Ttl: 60}, A: net.ParseIP("192.0.2.9")}}})
	_, current := one.DNSSnapshot()
	require.Equal(t, BuiltinDirect, current[record.Hostname].Proxy)
	require.Equal(t, "192.0.2.9", current[record.Hostname].RealIP.String())
	one.dnsTable.recordsLock.Lock()
	one.dnsTable.records[record.Hostname].resolvedExpires = time.Time{}
	before := cloneRecord(one.dnsTable.records[record.Hostname])
	one.dnsTable.recordsLock.Unlock()
	_, displayed := one.DNSSnapshot()
	require.Nil(t, displayed[record.Hostname].RealIP)
	require.Nil(t, displayed[record.Hostname].resolved)
	require.Equal(t, "office", displayed[record.Hostname].Proxy, "only current domain evidence remains available for display")
	require.Equal(t, record.IP.String(), displayed[record.Hostname].IP.String())
	one.dnsTable.recordsLock.Lock()
	internal := cloneRecord(one.dnsTable.records[record.Hostname])
	one.dnsTable.recordsLock.Unlock()
	require.Equal(t, before.Hits, internal.Hits)
	require.Equal(t, before.Expires, internal.Expires)
	require.Equal(t, "192.0.2.9", internal.RealIP.String(), "display cleanup changes only its returned clone")
	require.NotNil(t, internal.resolved)
	require.Zero(t, queries.Load(), "reading status never performs a DNS lookup")
}

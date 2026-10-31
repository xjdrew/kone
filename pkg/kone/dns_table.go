//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// hijacked domain
type DomainRecord struct {
	Hostname string // hostname
	Proxy    string // proxy

	IP      net.IP // nat ip
	RealIP  net.IP // real ip
	Hits    int
	Expires time.Time

	answer   *dns.A   // cache dns answer
	resolved *dns.Msg // original answers used to recompute IP/CNAME policy on reload
}

func cloneRecord(record *DomainRecord) *DomainRecord {
	if record == nil {
		return nil
	}
	copy := *record
	copy.IP = append(net.IP(nil), record.IP...)
	copy.RealIP = append(net.IP(nil), record.RealIP...)
	if record.answer != nil {
		copy.answer = dns.Copy(record.answer).(*dns.A)
	}
	if record.resolved != nil {
		copy.resolved = record.resolved.Copy()
	}
	return &copy
}

func (record *DomainRecord) SetRealIP(msg *dns.Msg) {
	if msg == nil {
		return
	}
	record.resolved = msg.Copy()
	if record.RealIP != nil {
		return
	}

	for _, item := range msg.Answer {
		switch answer := item.(type) {
		case *dns.A:
			record.RealIP = append(net.IP(nil), answer.A...)
			slog.Debug("DNS real address resolved", "domain", record.Hostname, "ip", answer.A)
			return
		}
	}
}

func (record *DomainRecord) Answer(request *dns.Msg) *dns.Msg {
	rsp := new(dns.Msg)
	rsp.SetReply(request)
	rsp.RecursionAvailable = true
	rsp.Answer = append(rsp.Answer, dns.Copy(record.answer))
	return rsp
}

func (record *DomainRecord) Touch() {
	record.Hits++
	record.Expires = time.Now().Add(time.Duration(record.answer.Hdr.Ttl) * time.Second)
}

type DnsTable struct {
	ipNet  netip.Prefix // local network
	ipPool *DnsIPPool   // dns ip pool
	ttl    uint32

	// hijacked domain records
	records     map[string]*DomainRecord // domain -> record
	ip2Domain   map[string]string        // ip -> domain: map hijacked ip address to domain
	recordsLock sync.Mutex               // protect records and ip2Domain
	pins        map[string]int           // active flows retain the domain/address association

	nonProxyDomains map[string]directRecord
	npdLock         sync.Mutex // protect non proxy domain
}

type directRecord struct {
	expires    time.Time
	generation uint64
}

func (c *DnsTable) IsLocalIP(ip net.IP) bool {
	address, _ := netip.AddrFromSlice(ip)
	return c.ipNet.Contains(address.Unmap())
}

func (c *DnsTable) get(domain string) *DomainRecord {
	record := c.records[domain]
	if record != nil {
		record.Touch()
	}
	return cloneRecord(record)
}

func (c *DnsTable) GetByIP(ip net.IP) *DomainRecord {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()
	if domain, ok := c.ip2Domain[ip.String()]; ok {
		return c.get(domain)
	}
	return nil
}

func (c *DnsTable) Contains(ip net.IP) bool {
	address, _ := netip.AddrFromSlice(ip)
	return c.ipPool.Contains(address.Unmap())
}

func (c *DnsTable) Get(domain string) *DomainRecord {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()
	return c.get(domain)
}

// forge a IPv4 dns reply
func forgeIPv4Answer(domain string, ip net.IP) *dns.A {
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: DnsDefaultTtl}
	rr.A = ip.To4()
	return rr
}

func (c *DnsTable) Set(domain string, proxy string) *DomainRecord {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()
	record := c.records[domain]
	if record != nil {
		record.Touch()
		return cloneRecord(record)
	}

	// alloc a ip
	address := c.ipPool.Alloc(domain)
	if !address.IsValid() {
		return nil
	}
	ip := net.IP(address.AsSlice())

	record = new(DomainRecord)
	record.IP = ip
	record.Hostname = domain
	record.Proxy = proxy
	record.answer = forgeIPv4Answer(domain, ip)
	record.answer.Hdr.Ttl = c.ttl

	c.records[domain] = record
	c.ip2Domain[ip.String()] = domain
	slog.Debug("Virtual IP allocated", "domain", domain, "ip", ip.String())

	record.Touch()
	return cloneRecord(record)
}

func (c *DnsTable) SetRealIP(domain string, msg *dns.Msg) {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()
	if record := c.records[domain]; record != nil {
		record.SetRealIP(msg)
	}
}

// Snapshot returns independently owned records for management/UI readers.
func (c *DnsTable) Snapshot() map[string]*DomainRecord {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()
	result := make(map[string]*DomainRecord, len(c.records))
	for name, record := range c.records {
		result[name] = cloneRecord(record)
	}
	return result
}

// RefreshPolicies preserves virtual addresses already cached by clients.
// The engine holds its policy write lock while this snapshot is updated.
func (c *DnsTable) RefreshPolicies(rule *Rule) {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()
	for _, record := range c.records {
		record.Proxy = rule.ProxyDNS(record.Hostname, record.resolved)
	}
	c.ClearNonProxyDomain()
}

func (c *DnsTable) IsNonProxyDomain(domain string, generation ...uint64) bool {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	record, ok := c.nonProxyDomains[domain]
	return ok && time.Now().Before(record.expires) && (len(generation) == 0 || record.generation == generation[0])
}

func (c *DnsTable) SetNonProxyDomain(domain string, ttl uint32, generation ...uint64) {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	var version uint64
	if len(generation) > 0 {
		version = generation[0]
	}
	if len(c.nonProxyDomains) >= 4096 {
		return
	}
	c.nonProxyDomains[domain] = directRecord{expires: time.Now().Add(time.Duration(ttl) * time.Second), generation: version}
	slog.Debug("Direct DNS entry cached", "domain", domain, "ttl", ttl)
}

func (c *DnsTable) clearExpiredNonProxyDomain(now time.Time) {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	for domain, expired := range c.nonProxyDomains {
		if expired.expires.Before(now) {
			delete(c.nonProxyDomains, domain)
			slog.Debug("Direct DNS entry expired", "domain", domain)
		}
	}
}

func (c *DnsTable) ClearNonProxyDomain() {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	for domain := range c.nonProxyDomains {
		delete(c.nonProxyDomains, domain)
		slog.Debug("Direct DNS entry cleared", "domain", domain)

	}
}

func (c *DnsTable) clearExpiredDomain(now time.Time) {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()

	threshold := 1000
	if threshold > c.ipPool.Capacity()/10 {
		threshold = c.ipPool.Capacity() / 10
	}

	if len(c.records) <= threshold {
		return
	}

	for domain, record := range c.records {
		if c.pins[domain] > 0 {
			continue
		}
		if !record.Expires.Before(now) {
			continue
		}
		delete(c.records, domain)
		delete(c.ip2Domain, record.IP.String())
		address, _ := netip.AddrFromSlice(record.IP)
		c.ipPool.Release(address)
		slog.Debug("Virtual IP released", "domain", domain, "ip", record.IP.String(), "hits", record.Hits)
	}
}

func (c *DnsTable) Serve(ctx context.Context) error {
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-tick.C:
			c.clearExpiredDomain(now)
			//TODO: is it necessary?
			c.clearExpiredNonProxyDomain(now)
		}
	}
}

func NewDnsTable(ip net.IP, subnet *net.IPNet) *DnsTable {
	c := new(DnsTable)
	c.ttl = DnsDefaultTtl
	address, _ := netip.AddrFromSlice(ip)
	ones, _ := subnet.Mask.Size()
	prefix := netip.PrefixFrom(address.Unmap(), ones)
	c.ipNet = prefix.Masked()
	c.ipPool = NewDnsIPPool(prefix)
	c.records = make(map[string]*DomainRecord)
	c.pins = make(map[string]int)
	c.ip2Domain = make(map[string]string)
	c.nonProxyDomains = make(map[string]directRecord)
	return c
}

// Pin keeps an established flow's Fake-IP mapping from being recycled. The
// returned release function is safe to call more than once or concurrently.
func (c *DnsTable) Pin(domain string) func() {
	c.recordsLock.Lock()
	if c.records[domain] == nil {
		c.recordsLock.Unlock()
		return func() {}
	}
	if c.pins == nil {
		c.pins = make(map[string]int)
	}
	c.pins[domain]++
	c.recordsLock.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.recordsLock.Lock()
			defer c.recordsLock.Unlock()
			c.pins[domain]--
			if c.pins[domain] == 0 {
				delete(c.pins, domain)
			}
		})
	}
}

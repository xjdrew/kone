//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"log/slog"
	"net"
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
	ipNet  *net.IPNet // local network
	ipPool *DnsIPPool // dns ip pool
	ttl    uint32

	// hijacked domain records
	records     map[string]*DomainRecord // domain -> record
	ip2Domain   map[string]string        // ip -> domain: map hijacked ip address to domain
	recordsLock sync.Mutex               // protect records and ip2Domain

	nonProxyDomains map[string]time.Time // non proxy domain
	npdLock         sync.Mutex           // protect non proxy domain
}

func (c *DnsTable) IsLocalIP(ip net.IP) bool {
	return c.ipNet.Contains(ip)
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
	return c.ipPool.Contains(ip)
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
	ip := c.ipPool.Alloc(domain)
	if ip == nil {
		return nil
	}

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

func (c *DnsTable) IsNonProxyDomain(domain string) bool {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	expires, ok := c.nonProxyDomains[domain]
	return ok && time.Now().Before(expires)
}

func (c *DnsTable) SetNonProxyDomain(domain string, ttl uint32) {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	c.nonProxyDomains[domain] = time.Now().Add(time.Duration(ttl) * time.Second)
	slog.Debug("Direct DNS entry cached", "domain", domain, "ttl", ttl)
}

func (c *DnsTable) clearExpiredNonProxyDomain(now time.Time) {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	for domain, expired := range c.nonProxyDomains {
		if expired.Before(now) {
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
		if !record.Expires.Before(now) {
			continue
		}
		delete(c.records, domain)
		delete(c.ip2Domain, record.IP.String())
		c.ipPool.Release(record.IP)
		slog.Debug("Virtual IP released", "domain", domain, "ip", record.IP.String(), "hits", record.Hits)
	}
}

func (c *DnsTable) Serve() error {
	tick := time.NewTicker(60 * time.Second)
	for now := range tick.C {
		c.clearExpiredDomain(now)
		//TODO: is it necessary?
		c.clearExpiredNonProxyDomain(now)
	}
	return nil
}

func NewDnsTable(ip net.IP, subnet *net.IPNet) *DnsTable {
	c := new(DnsTable)
	c.ttl = DnsDefaultTtl
	c.ipNet = subnet
	c.ipPool = NewDnsIPPool(ip, subnet)
	c.records = make(map[string]*DomainRecord)
	c.ip2Domain = make(map[string]string)
	c.nonProxyDomains = make(map[string]time.Time)
	return c
}

//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// hijacked domain
type DomainRecord struct {
	domain string // domain name
	proxy  string // proxy

	ip     net.IP // nat ip
	realIP net.IP // real ip

	answer *dns.A // cache dns answer

	touch time.Time
	hit   int
}

func (record *DomainRecord) SetRealIP(msg *dns.Msg) {
	if record.realIP != nil {
		return
	}

	var ip net.IP
	for _, item := range msg.Answer {
		switch answer := item.(type) {
		case *dns.A:
			ip = answer.A
			break
		}
	}
	record.realIP = ip
	logger.Debugf("[dns] %s real ip: %s", record.domain, ip)
}

func (record *DomainRecord) Answer(request *dns.Msg) *dns.Msg {
	rsp := new(dns.Msg)
	rsp.SetReply(request)
	rsp.Answer = append(rsp.Answer, record.answer)
	return rsp
}

func (record *DomainRecord) Touch() {
	record.hit++
	record.touch = time.Now()
}

type DnsTable struct {
	// dns ip pool
	ipPool *DnsIPPool

	// hijacked domain records
	records     map[string]*DomainRecord // domain -> record
	ip2Domain   map[string]string        // ip -> domain: map hijacked ip address to domain
	recordsLock sync.Mutex               // protect records and ip2Domain

	nonProxyDomains map[string]time.Time // non proxy domain
	npdLock         sync.Mutex           // protect non proxy domain
}

func (c *DnsTable) get(domain string) *DomainRecord {
	record := c.records[domain]
	if record != nil {
		record.Touch()
	}
	return record
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
	rr.Hdr = dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: dnsDefaultTtl}
	rr.A = ip.To4()
	return rr
}

func (c *DnsTable) Set(domain string, proxy string) *DomainRecord {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()
	record := c.records[domain]
	if record != nil {
		return record
	}

	// alloc a ip
	ip := c.ipPool.Alloc(domain)
	if ip == nil {
		logger.Errorf("[dns] ip space is used up, domain:%s", domain)
		return nil
	}

	record = new(DomainRecord)
	record.ip = ip
	record.domain = domain
	record.proxy = proxy
	record.answer = forgeIPv4Answer(domain, ip)

	record.Touch()

	c.records[domain] = record
	c.ip2Domain[ip.String()] = domain
	logger.Debugf("[dns] hijack %s -> %s", domain, ip.String())
	return record
}

func (c *DnsTable) IsNonProxyDomain(domain string) bool {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	_, ok := c.nonProxyDomains[domain]
	return ok
}

func (c *DnsTable) SetNonProxyDomain(domain string, ttl uint32) {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	c.nonProxyDomains[domain] = time.Now().Add(time.Duration(ttl) * time.Second)
	logger.Debugf("[dns] set non proxy domain: %s, ttl: %d", domain, ttl)
}

func (c *DnsTable) clearExpiredNonProxyDomain(now time.Time) {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	for domain, expired := range c.nonProxyDomains {
		if expired.Before(now) {
			delete(c.nonProxyDomains, domain)
			logger.Debugf("[dns] release non proxy domain: %s", domain)
		}
	}
}

func (c *DnsTable) clearExpiredDomain(now time.Time) {
	c.recordsLock.Lock()
	defer c.recordsLock.Unlock()

	expired := now.Add(-2 * dnsDefaultTtl * time.Second)
	for domain, record := range c.records {
		if !record.touch.Before(expired) {
			continue
		}
		delete(c.records, domain)
		delete(c.ip2Domain, record.ip.String())
		c.ipPool.Release(record.ip)
		logger.Debugf("[dns] release %s -> %s, hit: %d", domain, record.ip.String(), record.hit)
	}
}

func (c *DnsTable) Serve() error {
	tick := time.Tick(60 * time.Second)
	for now := range tick {
		c.clearExpiredDomain(now)
		c.clearExpiredNonProxyDomain(now)
	}
	return nil
}

func NewDnsTable(ip net.IP, subnet *net.IPNet) *DnsTable {
	c := new(DnsTable)
	c.ipPool = NewDnsIPPool(ip, subnet)
	c.records = make(map[string]*DomainRecord)
	c.ip2Domain = make(map[string]string)
	c.nonProxyDomains = make(map[string]time.Time)
	return c
}

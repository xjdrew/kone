//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"fmt"
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

	answer *dns.A // cache dns answer
}

func (record *DomainRecord) SetRealIP(msg *dns.Msg) {
	if record.RealIP != nil {
		return
	}

	for _, item := range msg.Answer {
		switch answer := item.(type) {
		case *dns.A:
			record.RealIP = answer.A
			logger.Debugf("[dns] %s real ip: %s", record.Hostname, answer.A)
			return
		}
	}
}

func (record *DomainRecord) Answer(request *dns.Msg) *dns.Msg {
	rsp := new(dns.Msg)
	rsp.SetReply(request)
	rsp.RecursionAvailable = true
	rsp.Answer = append(rsp.Answer, record.answer)
	return rsp
}

func (record *DomainRecord) Touch() {
	record.Hits++
	record.Expires = time.Now().Add(DnsDefaultTtl * time.Second)
}

type DnsTable struct {
	ipNet  *net.IPNet // local network
	ipPool *DnsIPPool // dns ip pool

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
		return record
	}

	// alloc a ip
	ip := c.ipPool.Alloc(domain)
	if ip == nil {
		panic(fmt.Sprintf("[dns] ip space is used up, domain:%s", domain))
	}

	record = new(DomainRecord)
	record.IP = ip
	record.Hostname = domain
	record.Proxy = proxy
	record.answer = forgeIPv4Answer(domain, ip)

	c.records[domain] = record
	c.ip2Domain[ip.String()] = domain
	logger.Debugf("[dns] hijack %s -> %s", domain, ip.String())

	record.Touch()
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
			logger.Debugf("[dns] release expired non proxy domain: %s", domain)
		}
	}
}

func (c *DnsTable) ClearNonProxyDomain() {
	c.npdLock.Lock()
	defer c.npdLock.Unlock()
	for domain := range c.nonProxyDomains {
		delete(c.nonProxyDomains, domain)
		logger.Debugf("[dns] release non proxy domain: %s", domain)

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
		logger.Debugf("[dns] release %s -> %s, hit: %d", domain, record.IP.String(), record.Hits)
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
	c.ipNet = subnet
	c.ipPool = NewDnsIPPool(ip, subnet)
	c.records = make(map[string]*DomainRecord)
	c.ip2Domain = make(map[string]string)
	c.nonProxyDomains = make(map[string]time.Time)
	return c
}

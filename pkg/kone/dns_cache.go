package kone

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsCacheEntry struct {
	message           *dns.Msg
	inserted, expires time.Time
	bytes             int
}
type dnsResponseCache struct {
	mu           sync.Mutex
	entries      map[string]dnsCacheEntry
	limit, bytes int
}

func newDNSResponseCache(limit int) *dnsResponseCache {
	if limit < 0 {
		limit = 0
	}
	if limit > 10000 {
		limit = 10000
	}
	return &dnsResponseCache{entries: make(map[string]dnsCacheEntry), limit: limit}
}

func dnsCacheKey(request *dns.Msg, route string) string {
	// Requests carrying EDNS options (including ECS/DO), TSIG or CD need their
	// own semantics; bypass this basic cache instead of mixing client contexts.
	if request == nil || len(request.Question) != 1 || len(request.Extra) > 0 || request.CheckingDisabled || !request.RecursionDesired {
		return ""
	}
	q := request.Question[0]
	return fmt.Sprintf("%s|%s|%d|%d", route, strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

func (c *dnsResponseCache) get(key string, id uint16, now time.Time) *dns.Msg {
	if c == nil || key == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !entry.expires.After(now) {
		delete(c.entries, key)
		c.bytes -= entry.bytes
		return nil
	}
	copy := entry.message.Copy()
	copy.Id = id
	age := uint32(now.Sub(entry.inserted) / time.Second)
	for _, section := range [][]dns.RR{copy.Answer, copy.Ns, copy.Extra} {
		for _, record := range section {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if age >= record.Header().Ttl {
				record.Header().Ttl = 0
			} else {
				record.Header().Ttl -= age
			}
		}
	}
	return copy
}

func cacheTTL(message *dns.Msg) uint32 {
	if message == nil || message.Truncated || (message.Rcode != dns.RcodeSuccess && message.Rcode != dns.RcodeNameError) {
		return 0
	}
	ttl := uint32(3600)
	found := false
	for _, record := range message.Answer {
		found = true
		if record.Header().Ttl < ttl {
			ttl = record.Header().Ttl
		}
	}
	if len(message.Answer) == 0 {
		for _, record := range message.Ns {
			if soa, ok := record.(*dns.SOA); ok {
				found = true
				if soa.Hdr.Ttl < ttl {
					ttl = soa.Hdr.Ttl
				}
				if soa.Minttl < ttl {
					ttl = soa.Minttl
				}
			}
		}
	}
	if !found {
		return 0
	}
	return ttl
}

func (c *dnsResponseCache) put(key string, message *dns.Msg, now time.Time) {
	if c == nil || c.limit == 0 || key == "" {
		return
	}
	ttl := cacheTTL(message)
	if ttl == 0 {
		return
	}
	size := message.Len()
	const byteLimit = 8 << 20
	if size > byteLimit {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.entries[key]; ok {
		c.bytes -= old.bytes
		delete(c.entries, key)
	}
	for len(c.entries) >= c.limit || c.bytes+size > byteLimit {
		var oldestKey string
		var oldest time.Time
		for k, entry := range c.entries {
			if oldestKey == "" || entry.inserted.Before(oldest) {
				oldestKey, oldest = k, entry.inserted
			}
		}
		if oldestKey == "" {
			break
		}
		c.bytes -= c.entries[oldestKey].bytes
		delete(c.entries, oldestKey)
	}
	c.entries[key] = dnsCacheEntry{message: message.Copy(), inserted: now, expires: now.Add(time.Duration(ttl) * time.Second), bytes: size}
	c.bytes += size
}

func (c *dnsResponseCache) prune(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if !entry.expires.After(now) {
			c.bytes -= entry.bytes
			delete(c.entries, key)
		}
	}
}

func (c *dnsResponseCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
	c.bytes = 0
}

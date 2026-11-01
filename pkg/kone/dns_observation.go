package kone

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSQueryEvent is a query observation, never evidence of a business connection.
// Event addresses distinguish virtual answers from upstream answers.
type DNSQueryEvent struct {
	ID                 string    `json:"id"`
	Time               time.Time `json:"time"`
	Name               string    `json:"name"`
	Type               string    `json:"type"`
	Source             string    `json:"source"`
	Scope              string    `json:"scope"`
	Transport          string    `json:"transport"`
	Upstream           string    `json:"upstream,omitempty"`
	UpstreamTransport  string    `json:"upstream_transport,omitempty"`
	ResolverInterface  string    `json:"resolver_interface,omitempty"`
	AttemptedResolvers []string  `json:"attempted_resolvers,omitempty"`
	Route              string    `json:"route,omitempty"`
	Status             string    `json:"status"`
	Error              string    `json:"error,omitempty"`
	DurationMS         float64   `json:"duration_ms"`
	Cache              string    `json:"cache"`
	Version            uint64    `json:"version"`
	VirtualAddresses   []string  `json:"virtual_addresses,omitempty"`
	RealAddresses      []string  `json:"real_addresses,omitempty"`
}

type dnsMetaKey struct{}
type dnsQueryMeta struct {
	Upstream, UpstreamTransport, Cache, Route string
	Virtual, Real                             []string
	AttemptedResolvers                        []string
	ResolverInterface                         string
}

type dnsHistory struct {
	mu        sync.Mutex
	entries   []DNSQueryEvent
	next      int
	sequence  uint64
	dropped   uint64
	retention time.Duration
}

func newDNSHistory(limit int, retention time.Duration) *dnsHistory {
	if limit < 0 {
		limit = 0
	}
	if limit > 10000 {
		limit = 10000
	}
	return &dnsHistory{entries: make([]DNSQueryEvent, limit), retention: retention}
}

func (h *dnsHistory) add(event DNSQueryEvent) {
	if h == nil || len(h.entries) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sequence++
	event.ID = fmt.Sprintf("dns-%d", h.sequence)
	if previous := h.entries[h.next]; previous.ID != "" && previous.Time.Add(h.retention).After(event.Time) {
		h.dropped++
	}
	h.entries[h.next] = event
	h.next = (h.next + 1) % len(h.entries)
}

func (h *dnsHistory) snapshot(now time.Time) []DNSQueryEvent {
	if h == nil {
		return []DNSQueryEvent{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]DNSQueryEvent, 0, len(h.entries))
	for i := 0; i < len(h.entries); i++ {
		index := (h.next - 1 - i + len(h.entries)) % len(h.entries)
		event := h.entries[index]
		if event.ID == "" {
			continue
		}
		if !event.Time.Add(h.retention).After(now) {
			h.entries[index] = DNSQueryEvent{}
			continue
		}
		event.RealAddresses = append([]string(nil), event.RealAddresses...)
		event.VirtualAddresses = append([]string(nil), event.VirtualAddresses...)
		event.AttemptedResolvers = append([]string(nil), event.AttemptedResolvers...)
		result = append(result, event)
	}
	return result
}

func (h *dnsHistory) clear() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.entries)
	h.next = 0
	h.dropped = 0
}

func (h *dnsHistory) prune(now time.Time) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, event := range h.entries {
		if event.ID != "" && !event.Time.Add(h.retention).After(now) {
			h.entries[i] = DNSQueryEvent{}
		}
	}
}

func (d *Dns) Queries() []DNSQueryEvent { return d.history.snapshot(time.Now()) }
func (d *Dns) ClearQueries()            { d.history.clear() }
func (d *Dns) ClearCache()              { d.cache.clear() }

func (d *Dns) recordQuery(request, reply *dns.Msg, err error, transport, source string, version uint64, start time.Time, meta *dnsQueryMeta) {
	if request == nil || len(request.Question) != 1 {
		return
	}
	event := DNSQueryEvent{Time: start, Name: normalizeDomain(request.Question[0].Name), Type: dns.TypeToString[request.Question[0].Qtype], Source: source, Scope: "dns", Transport: transport, Version: version, Status: "SERVFAIL", DurationMS: float64(time.Since(start)) / float64(time.Millisecond), Cache: "none"}
	if event.Type == "" {
		event.Type = fmt.Sprint(request.Question[0].Qtype)
	}
	if transport == "control" {
		event.Scope = "control"
		event.Transport = "internal"
	}
	if reply != nil {
		event.Status = dns.RcodeToString[reply.Rcode]
		event.RealAddresses = dnsAddresses(reply)
	}
	if err != nil {
		event.Error = err.Error()
	}
	if meta != nil {
		event.Upstream, event.UpstreamTransport, event.Route = meta.Upstream, meta.UpstreamTransport, meta.Route
		event.ResolverInterface = meta.ResolverInterface
		event.AttemptedResolvers = append([]string(nil), meta.AttemptedResolvers...)
		if meta.Cache != "" {
			event.Cache = meta.Cache
		}
		event.VirtualAddresses = append([]string(nil), meta.Virtual...)
		if len(meta.Virtual) > 0 {
			event.RealAddresses = append([]string(nil), meta.Real...)
		}
	}
	d.history.add(event)
}

func dnsAddresses(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	var addresses []string
	for _, answer := range msg.Answer {
		var value string
		switch record := answer.(type) {
		case *dns.A:
			value = record.A.String()
		case *dns.AAAA:
			value = record.AAAA.String()
		}
		if value != "" && len(addresses) < 64 {
			addresses = append(addresses, value)
		}
	}
	return addresses
}

func validDNSSuffix(suffix string) bool {
	if suffix == "." {
		return true
	}
	if suffix == "" || len(suffix) > 253 || strings.ContainsAny(suffix, "\x00\r\n\t /*\\") {
		return false
	}
	for _, ch := range suffix {
		if ch > 127 {
			return false
		}
	}
	_, valid := dns.IsDomainName(dns.Fqdn(suffix))
	return valid
}

func normalizeDNSSuffix(suffix string) string {
	if suffix == "." {
		return suffix
	}
	return normalizeDomain(suffix)
}

func (d *Dns) selectResolvers(name string) ([]string, string) {
	servers, suffix, _, _ := d.selectResolverRoute(name)
	return servers, suffix
}

func (d *Dns) selectResolverRoute(name string) ([]string, string, string, error) {
	name = normalizeDomain(name)
	best := -1
	servers, suffix := d.nameservers, ""
	selected := DNSRouteConfig{}
	for _, route := range d.routes {
		candidate := normalizeDNSSuffix(route.Suffix)
		score := 2 * len(candidate)
		if route.Exact {
			score++
		}
		if !route.Automatic {
			score += 1024
		}
		if (candidate == "." || name == candidate || !route.Exact && strings.HasSuffix(name, "."+candidate)) && score > best {
			best, servers, suffix, selected = score, route.Servers, candidate, route
		}
	}
	if selected.Unavailable {
		return nil, suffix, dnsRouteKey(selected), errors.New("exclusive system DNS scope unavailable: " + selected.Reason)
	}
	return servers, suffix, dnsRouteKey(selected), nil
}

// Maintain expires query records and caches even when no browser is connected.
func (d *Dns) Maintain(ctx context.Context) error {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	lastMappingSweep := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-timer.C:
			d.history.prune(now)
			d.cache.prune(now)
			if now.Sub(lastMappingSweep) >= time.Minute {
				d.one.dnsTable.clearExpiredDomain(now)
				d.one.dnsTable.clearExpiredNonProxyDomain(now)
				if d.one.dnsTable6 != nil {
					d.one.dnsTable6.clearExpiredDomain(now)
					d.one.dnsTable6.clearExpiredNonProxyDomain(now)
				}
				lastMappingSweep = now
			}
		}
	}
}

type DNSRuntimeStatus struct {
	Automatic               bool             `json:"automatic"`
	Servers                 []string         `json:"servers"`
	Rules                   []DNSRouteConfig `json:"rules"`
	HistoryLimit            int              `json:"history_limit"`
	HistoryRetentionSeconds int64            `json:"history_retention_seconds"`
	HistoryDropped          uint64           `json:"history_dropped"`
	CacheEntries            int              `json:"cache_entries"`
	CacheLimit              int              `json:"cache_limit"`
	TCP                     bool             `json:"tcp"`
	UpstreamTCP             bool             `json:"upstream_tcp"`
	IPv6                    bool             `json:"ipv6"`
	SystemSource            string           `json:"system_source"`
	SearchDomains           []string         `json:"search_domains"`
	Warnings                []string         `json:"warnings"`
}

func (one *One) DNSQueries() []DNSQueryEvent {
	if one == nil || one.dns == nil {
		return []DNSQueryEvent{}
	}
	return one.dns.Queries()
}
func (one *One) ClearDNSQueries() {
	if one != nil && one.dns != nil {
		one.dns.ClearQueries()
	}
}
func (one *One) ClearDNSCache() {
	if one != nil && one.dns != nil {
		one.dns.ClearCache()
	}
}
func (one *One) DNSStatus() DNSRuntimeStatus {
	status := DNSRuntimeStatus{Servers: []string{}, Rules: []DNSRouteConfig{}}
	if one == nil || one.dns == nil {
		return status
	}
	d := one.dns
	status.SystemSource = d.systemContext.Source
	status.SearchDomains = append([]string(nil), d.systemContext.SearchDomains...)
	status.Warnings = append([]string(nil), d.systemContext.Warnings...)
	status.IPv6 = one.dnsTable6 != nil
	status.Servers = append(status.Servers, d.nameservers...)
	for _, route := range d.routes {
		copy := route
		copy.Servers = append([]string(nil), route.Servers...)
		status.Rules = append(status.Rules, copy)
	}
	if snapshot := one.policy.Load(); snapshot != nil {
		status.Automatic = len(snapshot.cfg.DNS.Servers) == 0
	}
	if d.history != nil {
		d.history.mu.Lock()
		status.HistoryLimit = len(d.history.entries)
		status.HistoryRetentionSeconds = int64(d.history.retention / time.Second)
		status.HistoryDropped = d.history.dropped
		d.history.mu.Unlock()
	}
	if d.cache != nil {
		d.cache.mu.Lock()
		status.CacheEntries, status.CacheLimit = len(d.cache.entries), d.cache.limit
		d.cache.mu.Unlock()
	}
	status.TCP = d.tcpStarted.Load()
	status.UpstreamTCP = d.forceTCP
	return status
}

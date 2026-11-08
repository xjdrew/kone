package kone

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

type HealthQuery struct {
	Offset int
	Limit  int
	Status string
	Search string
}
type HealthState struct {
	Status      string           `json:"status"`
	Error       string           `json:"error,omitempty"`
	AutoEnabled bool             `json:"auto_enabled"`
	Entries     []HealthIncident `json:"entries"`
	Total       int              `json:"total"`
	Dropped     uint64           `json:"dropped"`
}
type HealthAction struct {
	Action     string `json:"action"`
	Domain     string `json:"domain"`
	Scope      string `json:"scope"`
	Generation uint64 `json:"generation"`
	Version    uint64 `json:"version"`
}
type healthEvent struct {
	manual bool

	domain, scope, reason string
	result                HealthResult
	message               *dns.Msg
	version               uint64
}
type healthChoice struct {
	address string

	outbound string
	port     uint16
	expires  time.Time
	version  uint64
	message  *dns.Msg
	network  string
}
type healthEvidence struct {
	results    []HealthResult
	proposed   map[uint16]healthChoice
	version    uint64
	generation uint64
	expires    time.Time
}
type connectionHealth struct {
	networkSample func(string) (string, error)

	dnsClient func(*http.Transport) *http.Client

	resolveLocal func(context.Context, string) (*dns.Msg, error)

	probeDial    func(context.Context, string, string, bool, uint64, diagnosticProbePlan) (DiagnosticResult, error)
	resolveProxy func(context.Context, *runtimeSnapshot, string, string) (*dns.Msg, error)

	one            *One
	mu             sync.Mutex
	ledger         *HealthLedger
	events         chan healthEvent
	jobs           chan healthEvent
	pending        map[string]bool
	latest         map[string]healthEvent
	due            map[string]time.Time
	evidence       map[string]healthEvidence
	choices        map[string]map[uint16]healthChoice
	failures       map[string]time.Time
	failureScopes  map[string]string
	ctx            context.Context
	cancel         context.CancelFunc
	errorText      string
	dropped        uint64
	network        string
	networkChecked time.Time
	tokens         float64
	refill         time.Time
}

func newConnectionHealth(one *One) *connectionHealth {
	ledger, _ := OpenHealthLedger("")
	h := &connectionHealth{one: one, probeDial: one.probeDiagnosticPlan, ledger: ledger, events: make(chan healthEvent, 128), jobs: make(chan healthEvent, 128), pending: map[string]bool{}, latest: map[string]healthEvent{}, due: map[string]time.Time{}, evidence: map[string]healthEvidence{}, choices: map[string]map[uint16]healthChoice{}, failures: map[string]time.Time{}, failureScopes: map[string]string{}, tokens: 6, refill: time.Now()}
	h.networkSample = smartNetworkFingerprint
	h.resolveLocal = func(ctx context.Context, domain string) (*dns.Msg, error) {
		return one.dns.ResolveContext(context.WithValue(ctx, healthNativeDNSKey{}, true), domain)
	}
	h.resolveProxy = h.proxyResolve
	return h
}
func (h *connectionHealth) invalidate() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.choices = map[string]map[uint16]healthChoice{}
	h.evidence = map[string]healthEvidence{}
	h.failures = map[string]time.Time{}
	h.failureScopes = map[string]string{}
	for key, e := range h.latest {
		e.version = h.one.policy.Load().version
		e.message = nil
		h.latest[key] = e
		h.due[key] = time.Now()
	}
	if h.cancel != nil {
		h.cancel()
		h.ctx, h.cancel = context.WithCancel(context.Background())
	}
}
func (h *connectionHealth) offer(e healthEvent) {
	if h == nil {
		return
	}
	if e.message != nil {
		e.message = e.message.Copy()
	}
	select {
	case h.events <- e:
	default:
		h.mu.Lock()
		h.dropped++
		h.mu.Unlock()
	}
}
func (h *connectionHealth) run(ctx context.Context) error {
	h.mu.Lock()
	h.ctx, h.cancel = context.WithCancel(ctx)
	root := h.one.fakeIPDirectory
	if root == "" {
		var err error
		root, err = fakeLedgerHostDirectory()
		if err != nil {
			h.errorText = err.Error()
		}
	}
	release := func() {}
	if root != "" {
		ledger, unlock, err := openRuntimeHealthLedger(root)
		if err != nil {
			h.errorText = err.Error()
		} else {
			h.ledger = ledger
			release = unlock
		}
	}
	defer release()
	h.ledger.mu.Lock()
	for key, entry := range h.ledger.entries {
		if len(h.latest) >= 512 {
			break
		}
		if entry.Status == "attention" || entry.Status == "adjusted" {
			h.latest[key] = healthEvent{domain: entry.Domain, scope: entry.Scope, version: h.one.policy.Load().version}
			h.due[key] = time.Now()
		}
	}
	h.ledger.mu.Unlock()
	h.mu.Unlock()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case e := <-h.jobs:
					h.check(e)
				}
			}
		}()
	}
	defer func() {
		h.mu.Lock()
		h.cancel()
		h.ctx = nil
		h.choices = map[string]map[uint16]healthChoice{}
		h.mu.Unlock()
		wg.Wait()
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-h.events:
			h.ledger.mu.Lock()
			closedAt := h.ledger.entries[healthKey(e.domain, e.scope)].ClosedAt
			h.ledger.mu.Unlock()
			if !closedAt.IsZero() && !e.result.Time.After(closedAt) {
				continue
			}
			if e.reason != "" {
				if _, err := h.ledger.Observe(e.domain, e.scope, e.reason, e.result); err != nil {
					h.storageError(err)
				}
			}
			key := healthKey(e.domain, e.scope)
			h.mu.Lock()
			if len(h.latest) < 512 || h.latest[key].domain != "" {
				h.latest[key] = e
				if h.due[key].IsZero() {
					h.due[key] = time.Now()
				}
			} else {
				// Rotate the bounded hot set instead of permanently ignoring new
				// targets once full. Persistent incident summaries are independent.
				oldest := ""
				for candidate, old := range h.latest {
					if !h.pending[candidate] && (oldest == "" || old.result.Time.Before(h.latest[oldest].result.Time)) {
						oldest = candidate
					}
				}
				if oldest != "" {
					delete(h.latest, oldest)
					delete(h.due, oldest)
					delete(h.evidence, oldest)
					delete(h.failures, oldest)
					delete(h.failureScopes, oldest)
					h.latest[key], h.due[key] = e, time.Now()
				} else {
					h.dropped++
				}
			}
			h.mu.Unlock()
		case now := <-tick.C:
			h.mu.Lock()
			if now.Sub(h.networkChecked) >= 5*time.Second {
				h.mu.Unlock()
				network, err := h.networkSample("")
				h.mu.Lock()
				h.networkChecked = now
				if err != nil {
					h.choices = map[string]map[uint16]healthChoice{}
					h.network = ""
				} else {
					if h.network != "" && h.network != network {
						h.choices = map[string]map[uint16]healthChoice{}
						h.evidence = map[string]healthEvidence{}
						h.failures = map[string]time.Time{}
						h.failureScopes = map[string]string{}
					}
					h.network = network
				}
			}
			for key, choices := range h.choices {
				for port, choice := range choices {
					if !now.Before(choice.expires) {
						delete(choices, port)
					}
				}
				if len(choices) == 0 {
					delete(h.choices, key)
				}
			}
			for key, evidence := range h.evidence {
				if !now.Before(evidence.expires) {
					delete(h.evidence, key)
				}
			}
			for key, e := range h.latest {
				if !h.pending[key] && !now.Before(h.due[key]) {
					select {
					case h.jobs <- e:
						// Explicit private-scope consent applies to this check only.
						e.manual = false
						h.latest[key] = e
						h.pending[key] = true
						h.due[key] = now.Add(time.Minute)
					default:
						h.dropped++
					}
				}
			}
			h.mu.Unlock()
		}
	}
}
func (h *connectionHealth) storageError(err error) {
	h.mu.Lock()
	h.errorText = err.Error()
	h.mu.Unlock()
}
func (h *connectionHealth) attempt(ctx context.Context) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.tokens = min(6, h.tokens+now.Sub(h.refill).Seconds()/2)
	h.refill = now
	if ctx.Err() != nil || h.tokens < 1 {
		return false
	}
	h.tokens--
	return true
}
func (h *connectionHealth) probe(ctx context.Context, s *runtimeSnapshot, outbound, domain string, port uint16, message *dns.Msg, manual ...bool) HealthResult {
	r := HealthResult{Protocol: "tcp", Port: port, Source: "probe", Outbound: outbound, Status: "unknown", Time: time.Now()}

	addresses := dnsAddresses(message)
	if len(addresses) == 0 {
		r.Stage = "dns"
		r.Status = "failed"
		return r
	}
	// Only a fixed, permitted endpoint is probed. Preserve the domain for TLS.
	decision := s.rule.DecideDNS(domain, message, "tcp", port)
	allowed := decision.Candidates
	if len(allowed) == 0 {
		allowed = addresses
	}
	for index, address := range allowed {
		if index >= 2 {
			r.Status = "unknown"
			r.Stage = "insufficient"
			return r
		}
		if !h.attempt(ctx) {
			r.Status = "unknown"
			r.Stage = "budget"
			return r
		}
		ip, err := netip.ParseAddr(address)
		if err != nil || (!smartPublicTarget(s, ip) && (len(manual) == 0 || !manual[0])) {
			continue
		}
		result, err := h.probeDial(ctx, outbound, net.JoinHostPort(address, strconv.Itoa(int(port))), port == 443 && net.ParseIP(domain) == nil, s.configurationVersion(), diagnosticProbePlan{serverName: domain})
		r.Address = address
		r.Stage, r.DurationMS, r.Message = result.Stage, result.DurationMS, result.Message
		if err == nil && result.Status == "reachable" {
			r.Status = "reachable"
			return r
		} else if err == nil && result.Status == "failed" && result.Stage != "target_tls" {
			r.Status = "failed"
		}
		if r.Status != "failed" {
			return r
		}
	}
	if r.Status == "failed" {
		return r
	}
	r.Stage = "scope"
	return r
}

// A separate, credential-free DNS request through the selected proxy supplies
// address evidence before any IP rule or protection can be evaluated. Private
// resolver scopes are excluded by the caller; the response is never a route.
func (h *connectionHealth) proxyResolve(ctx context.Context, s *runtimeSnapshot, outbound, domain string) (*dns.Msg, error) {
	if !h.attempt(ctx) {
		return nil, errors.New("probe budget exhausted")
	}
	q := new(dns.Msg).SetQuestion(dns.Fqdn(domain), dns.TypeA)
	wire, _ := q.Pack()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return s.outbounds.DialContext(ctx, outbound, "1.1.1.1:443")
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, "POST", "https://cloudflare-dns.com/dns-query", bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if h.dnsClient != nil {
		client = h.dnsClient(transport)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New("proxy DNS response rejected")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	if err = reply.Unpack(payload); err != nil {
		return nil, err
	}
	if !reply.Response || reply.Id != q.Id || len(reply.Question) != 1 || !strings.EqualFold(reply.Question[0].Name, q.Question[0].Name) || reply.Question[0].Qtype != dns.TypeA || reply.Rcode != dns.RcodeSuccess {
		return nil, errors.New("proxy DNS response does not match query")
	}
	aliases, addresses, valid := relatedDNSEvidence(domain, reply)
	if !valid || len(addresses) == 0 {
		return nil, errors.New("proxy DNS has no related addresses")
	}
	for _, alias := range aliases {
		_, scope, _, err := h.one.dns.selectResolverRoute(alias)
		if !smartDomain(alias) || scope != "" || err != nil {
			return nil, errors.New("proxy DNS alias outside automatic scope")
		}
	}
	for _, ip := range addresses {
		if !smartPublicTarget(s, ip) {
			return nil, errors.New("proxy DNS target outside automatic scope")
		}
	}
	return reply, nil
}
func healthSuccess(r HealthResult) bool { return r.Status == "reachable" }
func (h *connectionHealth) check(e healthEvent) {
	key := healthKey(e.domain, e.scope)
	h.mu.Lock()
	parent := h.ctx
	h.mu.Unlock()
	if parent == nil {
		return
	}
	defer func() { h.mu.Lock(); delete(h.pending, key); h.mu.Unlock() }()
	s := h.one.policy.Load()
	if e.version != s.version {
		return
	}
	checkStarted := time.Now()
	h.mu.Lock()
	probeNetwork := h.network
	h.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	// Passive private-scope failures are visible, but no public DNS query or
	// automatic probe is issued for that scope.
	_, route, _, routeErr := h.one.dns.selectResolverRoute(e.domain)
	privateScope := e.scope != "" || route != "" || routeErr != nil || (!smartDomain(e.domain) && net.ParseIP(e.domain) == nil)
	if privateScope && !e.manual {
		return
	}
	message := e.message
	if message != nil {
		message = message.Copy()
	}
	literal, ipErr := netip.ParseAddr(e.domain)
	if ipErr == nil {
		message = new(dns.Msg).SetQuestion(dns.Fqdn(e.domain), dns.TypeA)
		if literal.Is4() {
			message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(e.domain), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IP(literal.AsSlice())}}
		} else {
			message.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: dns.Fqdn(e.domain), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.IP(literal.AsSlice())}}
		}
	}
	if message != nil {
		for _, rr := range message.Answer {
			if ipErr != nil && (e.result.Time.IsZero() || !time.Now().Before(e.result.Time.Add(time.Duration(rr.Header().Ttl)*time.Second))) {
				message = nil
				break
			}
			if ipErr != nil {
				rr.Header().Ttl = uint32(max(0, time.Until(e.result.Time.Add(time.Duration(rr.Header().Ttl)*time.Second)).Seconds()))
			}
		}
	}
	if message == nil || len(dnsAddresses(message)) == 0 {
		message, _ = h.resolveLocal(ctx, e.domain)
	}
	localDNSOK := message != nil && len(dnsAddresses(message)) > 0
	proxy, hasProxy := preferredProxy(s.cfg)
	if (message == nil || len(dnsAddresses(message)) == 0) && hasProxy && !privateScope {
		message, _ = h.resolveProxy(ctx, s, proxy.Name, e.domain)
	}
	if message == nil || len(dnsAddresses(message)) == 0 {
		return
	}
	h.ledger.mu.Lock()
	prior := cloneHealthIncident(h.ledger.entries[key])
	h.ledger.mu.Unlock()
	ports := []uint16{80, 443}
	for _, r := range prior.Results {
		if r.Source == "business" && r.Protocol == "tcp" && r.Port != 0 && !slices.Contains(ports, r.Port) {
			ports = append(ports, r.Port)
		}
	}
	if e.result.Protocol == "tcp" && e.result.Port != 0 && e.result.Port != 80 && e.result.Port != 443 {
		ports = append(ports, e.result.Port)
	}
	dnsStatus := "answered"
	if !localDNSOK {
		dnsStatus = "failed"
	}
	results := []HealthResult{{Protocol: "dns", Source: "probe", Status: dnsStatus, Stage: "dns", Time: time.Now()}}
	proposed := map[uint16]healthChoice{}
	anySuccess := false
	allFailed := true
	businessOK := true
	for _, r := range prior.Results {
		if r.Source == "business" && r.Protocol != "tcp" && r.Protocol != "dns" && r.Status == "failed" {
			businessOK = false
		}
	}
	expiry := time.Now().Add(5 * time.Minute)
	for _, rr := range message.Answer {
		if t := time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second); t.Before(expiry) {
			expiry = t
		}
	}
	for _, port := range ports {
		decision := s.rule.DecideDNS(e.domain, message, "tcp", port)
		if decision.Protected || decision.CaptureOnly || decision.Evidence == "dns_failed" || decision.Outbound == BuiltinReject {
			allFailed = false
			continue
		}
		current := decision.Outbound
		r := h.probe(ctx, s, current, e.domain, port, message, e.manual)
		results = append(results, r)
		anySuccess = anySuccess || healthSuccess(r)
		allFailed = allFailed && r.Status == "failed"
		isBusiness := e.result.Source == "business" && e.result.Port == port
		for _, old := range prior.Results {
			if old.Source == "business" && old.Port == port && old.Protocol == "tcp" && old.Status == "failed" {
				isBusiness = true
			}
		}
		if isBusiness && !healthSuccess(r) {
			businessOK = false
		}
		if healthSuccess(r) || decision.DecisionSource != "base-final" || privateScope {
			continue
		}
		candidates := []string{}
		if hasProxy {
			candidates = append(candidates, proxy.Name)
		}
		for _, id := range s.cfg.Policy.Smart.Candidates {
			for _, o := range s.cfg.Outbounds {
				if o.ID == id && o.IsEnabled() {
					if !slices.Contains(candidates, o.Name) {
						candidates = append(candidates, o.Name)
					}
				}
			}
		}
		if s.cfg.Policy.Smart.AllowDirect {
			candidates = append(candidates, BuiltinDirect)
		}
		for _, outbound := range candidates {
			if outbound == current {
				continue
			}
			candidate := h.probe(ctx, s, outbound, e.domain, port, message)
			candidate.Source = "candidate"
			results = append(results, candidate)
			if healthSuccess(candidate) {
				h.mu.Lock()
				network := h.network
				h.mu.Unlock()
				proposed[port] = healthChoice{address: candidate.Address, outbound: outbound, port: port, expires: expiry, version: s.version, message: message.Copy(), network: network}
				break
			}
		}
	}
	if ctx.Err() != nil || h.one.policy.Load() != s {
		return
	}
	h.mu.Lock()
	networkChanged := h.network != probeNetwork
	h.mu.Unlock()
	if networkChanged {
		return
	}
	h.ledger.mu.Lock()
	closedAt := h.ledger.entries[key].ClosedAt
	h.ledger.mu.Unlock()
	if closedAt.After(checkStarted) {
		return
	}
	now := time.Now()
	reason := ""
	if !localDNSOK {
		reason = "dns_failed"
	}
	if allFailed && len(results) >= 2 {
		reason = "web_unreachable"
	}
	if !businessOK {
		reason = "business_failed"
	}
	if err := h.ledger.Refresh(e.domain, e.scope, results); err != nil {
		h.storageError(err)
		return
	}
	if reason != "" {
		for _, r := range results {
			if r.Source == "probe" && r.Status == "failed" {
				if _, err := h.ledger.Observe(e.domain, e.scope, reason, r); err != nil {
					h.storageError(err)
				}
			}
		}
	}
	h.ledger.mu.Lock()
	entry, exists := h.ledger.entries[key]
	generation := entry.Generation
	h.ledger.mu.Unlock()
	h.mu.Lock()
	h.evidence[key] = healthEvidence{results: results, proposed: proposed, version: s.version, generation: generation, expires: expiry}
	scopeKey := strings.Join(dnsAddresses(message), ",")
	if previous := h.failureScopes[key]; previous != "" && previous != scopeKey {
		delete(h.failures, key)
	}
	h.failureScopes[key] = scopeKey
	repeated := false
	if reason != "" {
		if at, ok := h.failures[key]; ok && now.Sub(at) >= 30*time.Second {
			repeated = true
		} else if !ok {
			h.failures[key] = now
		}
	} else {
		delete(h.failures, key)
	}
	coversBusiness := true
	for _, r := range prior.Results {
		if r.Source == "business" && r.Status == "failed" && r.Port != 0 {
			covered := false
			for _, now := range results {
				if now.Source == "probe" && now.Port == r.Port && now.Protocol == r.Protocol && healthSuccess(now) {
					covered = true
				}
			}
			if _, ok := proposed[r.Port]; ok && r.Protocol == "tcp" {
				covered = true
			}
			coversBusiness = coversBusiness && covered
		}
	}
	auto := s.cfg.Policy.Smart.AutoEnabled && repeated && h.errorText == "" && h.network != "" && len(proposed) > 0 && coversBusiness
	stillApplied := len(h.choices[key]) > 0
	for port, choice := range h.choices[key] {
		p, valid := proposed[port]
		stillApplied = stillApplied && valid && p.outbound == choice.outbound && now.Before(choice.expires)
	}
	if auto {
		h.choices[key] = proposed
	}
	h.mu.Unlock()
	if (auto || stillApplied) && exists {
		if err := h.ledger.Resolve(e.domain, e.scope, generation, func() string {
			if auto {
				return "automatic"
			}
			return "manual"
		}(), now); err != nil {
			h.storageError(err)
		}
	} else if exists && entry.Status == "attention" && (anySuccess || localDNSOK && entry.Reason == "dns_failed") && businessOK && reason == "" {
		if err := h.ledger.Resolve(e.domain, e.scope, generation, "retest", now); err != nil {
			h.storageError(err)
		}
	}
}
func (one *One) HealthData(q HealthQuery) (HealthState, error) {
	h := one.health
	if h == nil {
		return HealthState{}, errors.New("health unavailable")
	}
	h.mu.Lock()
	ledger := h.ledger
	h.mu.Unlock()
	entries, total := ledger.Filtered(q.Offset, q.Limit, q.Status, q.Search)
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range entries {
		key := healthKey(entries[i].Domain, entries[i].Scope)
		entries[i].Checking = h.pending[key] || !h.due[key].IsZero() && !time.Now().Before(h.due[key])
		if entries[i].Status == "adjusted" && len(h.choices[key]) == 0 {
			entries[i].Status = "checking"
		}
		if evidence, ok := h.evidence[key]; ok {
			entries[i].Results = append(entries[i].Results, evidence.results...)
			entries[i].Suggestions = map[uint16]string{}
			for port, choice := range evidence.proposed {
				entries[i].Suggestions[port] = choice.outbound
			}
			entries[i].Expires = evidence.expires
		}
		if choices := h.choices[key]; len(choices) > 0 {
			entries[i].Temporary = map[uint16]string{}
			for port, choice := range choices {
				if time.Now().Before(choice.expires) {
					entries[i].Temporary[port] = choice.outbound
				}
			}
		}
	}
	state := HealthState{Status: "running", AutoEnabled: one.policy.Load().cfg.Policy.Smart.AutoEnabled, Entries: entries, Total: total, Dropped: h.dropped, Error: h.errorText}
	if h.ctx == nil {
		state.Status = "paused"
	}
	return state, nil
}
func (one *One) HealthAction(a HealthAction) (HealthIncident, error) {
	h := one.health
	if h == nil {
		return HealthIncident{}, errors.New("health unavailable")
	}
	h.mu.Lock()
	ledger := h.ledger
	h.mu.Unlock()
	key := healthKey(a.Domain, a.Scope)
	ledger.mu.Lock()
	entry, ok := ledger.entries[key]
	entry = cloneHealthIncident(entry)
	ledger.mu.Unlock()
	if !ok || entry.Generation != a.Generation {
		return entry, errors.New("health incident changed")
	}
	switch a.Action {
	case "handled":
		err := ledger.Resolve(a.Domain, a.Scope, a.Generation, "user", time.Now())
		if err == nil {
			h.mu.Lock()
			delete(h.latest, key)
			delete(h.due, key)
			delete(h.evidence, key)
			delete(h.failures, key)
			delete(h.failureScopes, key)
			h.mu.Unlock()
		}
		return entry, err
	case "recheck":
		h.mu.Lock()
		e := h.latest[key]
		e.version = one.policy.Load().version
		e.manual = true
		e.message = nil
		if e.domain == "" {
			e = healthEvent{domain: entry.Domain, scope: entry.Scope, version: one.policy.Load().version, manual: true}
		}
		h.latest[key] = e
		h.due[key] = time.Now()
		h.mu.Unlock()
		return entry, nil
	case "apply", "pin":
		h.mu.Lock()
		defer h.mu.Unlock()
		s := one.policy.Load()
		e, valid := h.evidence[key]
		if !valid || e.generation != a.Generation || e.version != s.version || a.Version != s.configurationVersion() || !time.Now().Before(e.expires) || len(e.proposed) == 0 || h.network == "" {
			return entry, errors.New("health evidence expired; recheck")
		}
		entry.Suggestions = map[uint16]string{}
		for port, choice := range e.proposed {
			decision := s.rule.DecideDNS(a.Domain, choice.message, "tcp", port)
			if decision.DecisionSource != "base-final" || decision.Protected {
				return entry, errors.New("manual rules take priority")
			}
			entry.Suggestions[port] = choice.outbound
		}
		if a.Action == "apply" {
			h.choices[key] = e.proposed
			return entry, ledger.Resolve(a.Domain, a.Scope, a.Generation, "manual", time.Now())
		}
		return entry, nil
	default:
		return entry, fmt.Errorf("unknown health action %q", a.Action)
	}
}
func (h *connectionHealth) selected(domain string, port uint16, s *runtimeSnapshot) (healthChoice, bool) {
	if h == nil {
		return healthChoice{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	choices := h.choices[healthKey(domain, "")]
	choice, ok := choices[port]
	if !ok || choice.version != s.version || choice.network != h.network || h.network == "" || !time.Now().Before(choice.expires) {
		return healthChoice{}, false
	}
	return choice, true
}
func (h *connectionHealth) dnsEvidence(domain string, s *runtimeSnapshot) *dns.Msg {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, choice := range h.choices[healthKey(domain, "")] {
		if choice.version == s.version && choice.network == h.network && h.network != "" && time.Now().Before(choice.expires) {
			return choice.message.Copy()
		}
	}
	return nil
}
func (h *connectionHealth) route(domain string, port uint16, protocol string, decision RoutingDecision, s *runtimeSnapshot) RoutingDecision {
	if decision.DecisionSource != "base-final" || decision.Protected || decision.CaptureOnly || protocol != "tcp" {
		return decision
	}
	if choice, ok := h.selected(domain, port, s); ok {
		if !slices.Contains(decision.Candidates, choice.address) && domain != choice.address {
			return decision
		}
		decision.Outbound = choice.outbound
		decision.Candidates = []string{choice.address}
		decision.DecisionSource = "smart-temporary"
		decision.Reason = "validated temporary health selection"
	}
	return decision
}

func (one *One) observeHealthFlow(s *runtimeSnapshot, protocol string, destination M.Socksaddr, outbound, stage string, err error) {
	if !reportableFlowError(err, stage) {
		return
	}
	domain := destination.Addr.String()
	if table := one.tableForAddress(destination.Addr); table != nil {
		if record := table.GetByIP(net.IP(destination.Addr.AsSlice())); record != nil {
			domain = record.Hostname
		}
	}
	one.health.offer(healthEvent{domain: domain, version: s.version, reason: "business_failed", result: HealthResult{Protocol: protocol, Port: destination.Port, Source: "business", Outbound: outbound, Status: "failed", Stage: stage, Time: time.Now()}})
}

type healthNativeDNSKey struct{}

func openRuntimeHealthLedger(root string) (*HealthLedger, func(), error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, nil, err
	}
	if err := verifyFakeLedgerPath(root, true); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(root, "connection-health.lock")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, err
	}
	if err = verifyFakeLedgerPath(path, false); err == nil {
		err = lockFakeLedger(lock)
	}
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	release := func() { _ = unlockFakeLedger(lock); _ = lock.Close() }
	file := filepath.Join(root, "connection-health-ledger.json")
	if _, err = os.Lstat(file); err == nil {
		if err = verifyFakeLedgerPath(file, false); err != nil {
			release()
			return nil, nil, err
		}
	}
	ledger, err := OpenHealthLedger(file)
	if err != nil {
		release()
		return nil, nil, err
	}
	return ledger, release, nil
}

func healthDNSFamily(message *dns.Msg, kind uint16) bool {
	for _, rr := range message.Answer {
		if rr.Header().Rrtype == kind {
			return true
		}
	}
	return false
}

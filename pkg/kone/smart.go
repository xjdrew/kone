package kone

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Smart is opt-in, bounded background evidence. It never changes routing.
type SmartConfig struct {
	AutoEnabled bool     `toml:"auto-enabled,omitempty" json:"auto-enabled"`
	Candidates  []string `toml:"candidates,omitempty" json:"candidates,omitempty"`
	AllowDirect bool     `toml:"allow-direct,omitempty" json:"allow-direct"`
	Enabled     bool     `toml:"enabled,omitempty" json:"enabled"`
}
type SmartSample struct {
	IP          string    `json:"ip"`
	Outbound    string    `json:"outbound"`
	Status      string    `json:"status"`
	Stage       string    `json:"stage"`
	DurationMS  int64     `json:"duration_ms"`
	Time        time.Time `json:"time"`
	VerifiedTLS bool      `json:"verified_tls"`
}
type SmartSuggestion struct {
	ID                string        `json:"id"`
	Domain            string        `json:"domain"`
	Status            string        `json:"status"`
	Action            string        `json:"suggested_action,omitempty"`
	Outbound          string        `json:"outbound,omitempty"`
	OutboundID        string        `json:"outbound_id,omitempty"`
	ConfigVersion     uint64        `json:"config_version"`
	NetworkGeneration string        `json:"network_generation"`
	Interface         string        `json:"interface,omitempty"`
	ResolverScope     string        `json:"resolver_scope"`
	Port              uint16        `json:"port"`
	Protocol          string        `json:"protocol"`
	PortSource        string        `json:"port_source"`
	ObservedAt        time.Time     `json:"observed_at"`
	ExpiresAt         time.Time     `json:"expires_at"`
	Candidates        []string      `json:"candidates"`
	Samples           []SmartSample `json:"samples"`
}
type SmartState struct {
	Enabled     bool              `json:"enabled"`
	Status      string            `json:"status"`
	Suggestions []SmartSuggestion `json:"suggestions"`
	Dropped     uint64            `json:"dropped"`
	Attempts    uint64            `json:"attempts"`
}
type SmartAction struct {
	Action  string `json:"action"`
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}
type SmartActionResult struct {
	Suggestion *SmartSuggestion `json:"suggestion,omitempty"`
}
type smartCandidate struct {
	ip      netip.Addr
	expires time.Time
}
type smartEntry struct {
	SmartSuggestion
	candidates    []smartCandidate
	version       uint64
	due, cooldown time.Time
	running       bool
	task          uint64
	cancel        context.CancelFunc
}
type smartWork struct {
	domain     string
	entry      *smartEntry
	generation uint64
	ctx        context.Context
}
type smartCoordinator struct {
	one               *One
	mu                sync.Mutex
	networkMu         sync.Mutex
	networkChecked    time.Time
	ownedTun          string
	entries           map[string]*smartEntry
	queue             chan smartWork
	ctx               context.Context
	cancel            context.CancelFunc
	generation        uint64
	network           string
	blocked           bool
	dropped, attempts uint64
	recentAttempts    []time.Time
	tokens            float64
	refill            time.Time
	now               func() time.Time
	probe             func(context.Context, string, string, string, uint64) (DiagnosticResult, error)
	networkSample     func(string) (string, error)
}

func newSmartCoordinator(one *One) *smartCoordinator {
	return &smartCoordinator{one: one, entries: map[string]*smartEntry{}, queue: make(chan smartWork, 128), now: time.Now, tokens: 6, refill: time.Now(), networkSample: smartNetworkFingerprint, probe: func(ctx context.Context, outbound, ip, domain string, version uint64) (DiagnosticResult, error) {
		return one.probeDiagnosticPlan(ctx, outbound, net.JoinHostPort(ip, "443"), true, version, diagnosticProbePlan{serverName: domain})
	}}
}
func preferredProxy(cfg *KoneConfig) (OutboundConfig, bool) {
	for _, out := range cfg.Outbounds {
		if out.ID != "" && out.ID == cfg.Policy.PreferredProxyID && out.IsEnabled() {
			return out, true
		}
	}
	return OutboundConfig{}, false
}
func (s *smartCoordinator) invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.generation++
	if s.ctx != nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
	for _, e := range s.entries {
		e.Status = "expired"
		e.Action = ""
		e.running = false
		e.due = time.Time{}
	}
}
func (s *smartCoordinator) run(ctx context.Context, ownedTun string) error {
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.ownedTun = ownedTun
	s.generation++
	s.mu.Unlock()
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case work := <-s.queue:
					s.execute(work)
				}
			}
		}()
	}
	defer func() {
		s.mu.Lock()
		s.cancel()
		s.ctx = nil
		for _, e := range s.entries {
			e.Status = "expired"
			e.Action = ""
		}
		s.mu.Unlock()
		workers.Wait()
	}()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	var lastNetwork time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			snapshot := s.one.policy.Load()
			if !snapshot.cfg.Policy.Smart.Enabled {
				continue
			}
			now := s.now()
			if now.Sub(lastNetwork) >= 5*time.Second {
				s.checkNetwork(true)
				lastNetwork = now
			}
			s.schedule(now)
		}
	}
}
func (s *smartCoordinator) schedule(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || s.ctx == nil || s.network == "" {
		return
	}
	for domain, e := range s.entries {
		if !now.Before(e.ExpiresAt) {
			if e.Status != "ignored" {
				e.Status = "expired"
				e.Action = ""
			}
			e.due = time.Time{}
			continue
		}
		if e.running || e.due.IsZero() || now.Before(e.due) {
			continue
		}
		e.task++
		taskCtx, cancel := context.WithCancel(s.ctx)
		e.cancel = cancel
		work := smartWork{domain: domain, entry: cloneSmartEntry(e), generation: s.generation, ctx: taskCtx}
		select {
		case s.queue <- work:
			e.running = true
			e.Status = "queued"
		default:
			cancel()
			s.dropped++
			return
		}
	}
}
func cloneSmartEntry(e *smartEntry) *smartEntry {
	copy := *e
	copy.Candidates = slices.Clone(e.Candidates)
	copy.Samples = slices.Clone(e.Samples)
	copy.candidates = slices.Clone(e.candidates)
	return &copy
}

// observe executes no I/O and never waits on workers or a contended lock. The
// original DNS message remains owned by the request and is copied only boundedly.
func (s *smartCoordinator) observe(snapshot *runtimeSnapshot, domain string, meta *dnsQueryMeta) {
	if s == nil || !snapshot.cfg.Policy.Smart.Enabled || meta == nil || meta.Origin != DNSOriginBusiness || meta.Resolved == nil || meta.Route != "" || !smartDomain(domain) || meta.Routing.DecisionSource != "base-final" || meta.Routing.CaptureOnly {
		return
	}
	msg := meta.Resolved
	if len(msg.Answer) > 80 || len(msg.Question) != 1 || msg.Question[0].Qtype != dns.TypeA && msg.Question[0].Qtype != dns.TypeAAAA {
		return
	}
	aliases, addresses, valid := relatedDNSEvidence(domain, msg)
	if !valid || len(addresses) == 0 {
		return
	}
	for _, alias := range aliases {
		if !smartDomain(alias) {
			return
		}
		_, scope, _, err := s.one.dns.selectResolverRoute(alias)
		if scope != "" || err != nil {
			return
		}
	}
	for _, ip := range addresses {
		if !smartPublicTarget(snapshot, ip) {
			return
		}
	}
	decision := snapshot.rule.DecideDNS(domain, msg, "tcp", 443)
	if decision.DecisionSource != "base-final" || decision.CaptureOnly || decision.Protected {
		return
	}
	ttl := uint32(300)
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl < 31 {
		return
	}
	if !s.mu.TryLock() {
		return
	}
	defer s.mu.Unlock()
	if s.ctx == nil || s.blocked {
		return
	}
	now := s.now()
	expiry := now.Add(time.Duration(ttl) * time.Second)
	e := s.entries[domain]
	if e != nil && e.version == snapshot.version && now.Before(e.cooldown) {
		return
	}
	if e == nil || e.version != snapshot.version || !now.Before(e.ExpiresAt) {
		if len(s.entries) >= 512 && e == nil {
			var oldest string
			var at time.Time
			for key, item := range s.entries {
				if !item.running && (oldest == "" || item.ObservedAt.Before(at)) {
					oldest, at = key, item.ObservedAt
				}
			}
			if oldest == "" {
				s.dropped++
				return
			}
			delete(s.entries, oldest)
		}
		sum := sha256.Sum256([]byte(domain + "\x00" + now.UTC().Format(time.RFC3339Nano)))
		e = &smartEntry{SmartSuggestion: SmartSuggestion{ID: hex.EncodeToString(sum[:12]), Domain: domain, Status: "pending", ConfigVersion: snapshot.configurationVersion(), NetworkGeneration: s.network, Interface: snapshot.cfg.Core.OutboundInterface, ResolverScope: "default", Port: 443, Protocol: "tcp+tls", PortSource: "web_default", ObservedAt: now, ExpiresAt: expiry, Samples: []SmartSample{}}, version: snapshot.version, due: now}
		s.entries[domain] = e
	}
	// Replace only this address family. A rotated endpoint cannot borrow old
	// evidence, and a newly observed sibling invalidates an in-flight verdict.
	next := []smartCandidate{}
	for _, candidate := range e.candidates {
		if candidate.ip.Is4() != addresses[0].Is4() {
			next = append(next, candidate)
		}
	}
	changed := false
	for _, ip := range addresses {
		candidate := smartCandidate{ip: ip, expires: expiry}
		old := slices.IndexFunc(e.candidates, func(c smartCandidate) bool { return c.ip == ip })
		if old >= 0 {
			candidate.expires = e.candidates[old].expires
		} else {
			changed = true
		}
		next = append(next, candidate)
	}
	if len(next) != len(e.candidates) {
		changed = true
	}
	if len(next) > 64 {
		return
	}
	if changed {
		if e.cancel != nil {
			e.cancel()
		}
		e.task++
		e.running = false
		e.Samples = nil
		e.Action = ""
		e.Status = "pending"
		e.due = now
	}
	e.candidates = next
	e.Candidates = nil
	for _, candidate := range next {
		e.Candidates = append(e.Candidates, candidate.ip.String())
		if candidate.expires.Before(e.ExpiresAt) {
			e.ExpiresAt = candidate.expires
		}
	}

}
func (s *smartCoordinator) takeAttempt(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.tokens = min(6, s.tokens+now.Sub(s.refill).Seconds()/2)
	s.refill = now
	s.recentAttempts = slices.DeleteFunc(s.recentAttempts, func(at time.Time) bool { return !at.After(now.Add(-time.Minute)) })
	if s.tokens < 1 || len(s.recentAttempts) >= 30 {
		return false
	}
	s.tokens--
	s.recentAttempts = append(s.recentAttempts, now)
	s.attempts++
	return true
}
func (s *smartCoordinator) execute(work smartWork) {
	defer func() {
		if work.entry.cancel != nil {
			work.entry.cancel()
		}
	}()
	e := work.entry
	s.mu.Lock()
	current := s.entries[work.domain]
	if current == nil || current.task != e.task || current.ID != e.ID || work.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	current.Status = "testing"
	s.mu.Unlock()
	snapshot := s.one.policy.Load()
	if snapshot.version != e.version || !snapshot.cfg.Policy.Smart.Enabled {
		s.finish(work, nil, "expired", time.Time{})
		return
	}
	ctx, cancel := context.WithTimeout(work.ctx, 15*time.Second)
	defer cancel()
	if !s.checkNetwork(false) || ctx.Err() != nil {
		s.finish(work, nil, "expired", time.Time{})
		return
	}
	mode, _ := PolicyMode(snapshot.cfg)
	proxy, hasProxy := preferredProxy(snapshot.cfg)
	samples := slices.Clone(e.Samples)
	budget := false
	// At most two candidates per batch, preferring one from each address family.
	candidates := slices.Clone(e.candidates)
	slices.SortFunc(candidates, func(a, b smartCandidate) int { return a.ip.Compare(b.ip) })
	if len(candidates) > 2 {
		last := candidates[len(candidates)-1]
		candidates = candidates[:2]
		if candidates[0].ip.Is4() && last.ip.Is6() {
			candidates[1] = last
		}
	}
	for _, candidate := range candidates {
		if ctx.Err() != nil || !s.now().Before(candidate.expires) || !smartPublicTarget(snapshot, candidate.ip) {
			continue
		}
		// Revalidate the actual address against current user and system rules.
		ipDecision := snapshot.rule.Decide(net.IP(candidate.ip.AsSlice()), "tcp", 443)
		if ipDecision.DecisionSource != "base-final" || ipDecision.Protected {
			continue
		}
		if !s.takeAttempt(ctx) {
			budget = true
			break
		}
		probeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		result, err := s.probe(probeCtx, BuiltinDirect, candidate.ip.String(), e.Domain, e.ConfigVersion)
		stop()
		sample := smartResultSample(candidate.ip, BuiltinDirect, result, err, s.now())
		samples = append(samples, sample)
		if !sample.VerifiedTLS && hasProxy && mode == "direct-first" && smartComparableFailure(sample) {
			if !s.takeAttempt(ctx) {
				budget = true
				break
			}
			probeCtx, stop = context.WithTimeout(ctx, 5*time.Second)
			result, err = s.probe(probeCtx, proxy.Name, candidate.ip.String(), e.Domain, e.ConfigVersion)
			stop()
			samples = append(samples, smartResultSample(candidate.ip, proxy.Name, result, err, s.now()))
		}
	}
	if len(samples) > 16 {
		samples = samples[len(samples)-16:]
	}
	e.Samples = samples
	status, action := smartConclusion(e, mode, s.now())
	e.Action = action
	if action == "direct" {
		e.Outbound = BuiltinDirect
	} else if action == "proxy" {
		e.Outbound = proxy.Name
		e.OutboundID = proxy.ID
	}
	due := time.Time{}
	if action == "" && s.now().Add(31*time.Second).Before(e.ExpiresAt) {
		// Two spaced batches are enough. Budget deferrals do not count as a batch.
		earliest := time.Time{}
		for _, sample := range samples {
			if earliest.IsZero() || sample.Time.Before(earliest) {
				earliest = sample.Time
			}
		}
		if budget {
			status = "budget"
			due = s.now().Add(10 * time.Second)
		} else if earliest.IsZero() || s.now().Sub(earliest) < 30*time.Second {
			status = "rechecking"
			due = s.now().Add(30 * time.Second)
		}
	}
	s.finish(work, e, status, due)
}
func smartResultSample(ip netip.Addr, outbound string, r DiagnosticResult, err error, now time.Time) SmartSample {
	sample := SmartSample{IP: ip.String(), Outbound: outbound, Status: r.Status, Stage: r.Stage, DurationMS: r.DurationMS, Time: now, VerifiedTLS: r.Protocols.TLS.Status == "healthy" && r.Protocols.TLS.Tested}
	if r.FailureKind == "timeout" && sample.Stage == "target_tls" {
		sample.Stage = "target_tls_timeout"
	}
	if err != nil {
		sample.Status = "unknown"
		sample.Stage = "engine"
	}
	return sample
}
func smartComparableFailure(s SmartSample) bool {
	return s.Status == "failed" && (s.Stage == "connect" || s.Stage == "target_connect" || s.Stage == "target_tls_timeout")
}
func smartConclusion(e *smartEntry, mode string, now time.Time) (string, string) {
	if !now.Before(e.ExpiresAt) {
		return "expired", ""
	}
	successes := map[string][]time.Time{}
	failures := map[string][]time.Time{}
	proxies := map[string]bool{}
	for _, sample := range e.Samples {
		if sample.Outbound == BuiltinDirect {
			if sample.VerifiedTLS {
				successes[sample.IP] = append(successes[sample.IP], sample.Time)
			} else if smartComparableFailure(sample) {
				failures[sample.IP] = append(failures[sample.IP], sample.Time)
			}
		} else if sample.VerifiedTLS {
			proxies[sample.IP] = true
		}
	}
	repeated := func(times []time.Time) bool {
		return len(times) >= 2 && times[len(times)-1].Sub(times[0]) >= 30*time.Second
	}
	for _, times := range successes {
		if mode == "proxy-first" && repeated(times) {
			return "ready", "direct"
		}
	}
	if len(successes) > 0 {
		return "direct_verified", ""
	}
	if mode == "direct-first" && len(e.candidates) > 0 {
		all := true
		for _, c := range e.candidates {
			if !repeated(failures[c.ip.String()]) || !proxies[c.ip.String()] {
				all = false
			}
		}
		if all {
			return "ready", "proxy"
		}
	}
	return "insufficient", ""
}
func (s *smartCoordinator) finish(work smartWork, e *smartEntry, status string, due time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.entries[work.domain]
	if current == nil || current.Status == "ignored" || current.ID != work.entry.ID || current.task != work.entry.task || s.generation != work.generation || work.ctx.Err() != nil {
		return
	}
	current.running = false
	if s.one.policy.Load().version != current.version || s.blocked {
		current.Status = "expired"
		current.due = time.Time{}
		return
	}
	if e != nil {
		current.Samples = e.Samples
		current.Action = e.Action
		current.Outbound = e.Outbound
		current.OutboundID = e.OutboundID
	}
	current.Status = status
	current.due = due
	current.NetworkGeneration = s.network
	if due.IsZero() {
		current.cooldown = s.now().Add(10 * time.Minute)
	}
	failedDomains := 0
	for _, item := range s.entries {
		recentFailure := false
		verifiedDirect := false
		for _, sample := range item.Samples {
			if sample.Outbound != BuiltinDirect || s.now().Sub(sample.Time) > time.Minute {
				continue
			}
			if sample.VerifiedTLS {
				verifiedDirect = true
			}
			if smartComparableFailure(sample) {
				recentFailure = true
			}
		}
		if recentFailure && !verifiedDirect {
			failedDomains++
		}
	}
	if failedDomains >= 4 {
		for _, item := range s.entries {
			if item.Action == "proxy" {
				item.Action = ""
				item.Status = "network_uncertain"
				item.due = time.Time{}
			}
		}
	}
}
func (one *One) SmartData() (SmartState, error) {
	s := one.smart
	state := SmartState{Enabled: one.policy.Load().cfg.Policy.Smart.Enabled, Status: "disabled", Suggestions: []SmartSuggestion{}}
	if s == nil {
		return state, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.Enabled {
		state.Status = "observing"
		if s.ctx == nil {
			state.Status = "paused"
		}
		if s.blocked {
			state.Status = "network_changed"
		}
	}
	state.Dropped, state.Attempts = s.dropped, s.attempts
	for _, e := range s.entries {
		copy := cloneSmartEntry(e).SmartSuggestion
		if (copy.Status == "expired" || !s.now().Before(copy.ExpiresAt)) && copy.Status != "ignored" {
			copy.Status = "expired"
			copy.Action = ""
		}
		state.Suggestions = append(state.Suggestions, copy)
	}
	sort.Slice(state.Suggestions, func(i, j int) bool { return state.Suggestions[i].ObservedAt.After(state.Suggestions[j].ObservedAt) })
	return state, nil
}
func (one *One) SmartAction(request SmartAction) (SmartActionResult, error) {
	s := one.smart
	if s == nil {
		return SmartActionResult{}, errors.New("Smart unavailable")
	}
	if request.Action == "preview" || request.Action == "recheck" {
		if !s.checkNetwork(true) {
			return SmartActionResult{}, errors.New("network context changed; restart capture before reviewing Smart evidence")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.Action == "clear" {
		s.cancelCurrentLocked()
		s.entries = map[string]*smartEntry{}
		return SmartActionResult{}, nil
	}
	for _, e := range s.entries {
		if e.ID != request.ID {
			continue
		}
		if request.Action == "ignore" {
			if e.cancel != nil {
				e.cancel()
			}
			e.task++
			e.running = false
			e.Status = "ignored"
			e.Action = ""
			e.due = time.Time{}
			e.cooldown = s.now().Add(10 * time.Minute)
			return SmartActionResult{}, nil
		}
		snapshot := one.policy.Load()
		if s.blocked || s.ctx == nil || snapshot.version != e.version || request.Version != e.ConfigVersion || !s.now().Before(e.ExpiresAt) || !snapshot.cfg.Policy.Smart.Enabled {
			return SmartActionResult{}, errors.New("Smart evidence expired; wait for a new business DNS query")
		}
		if request.Action == "recheck" {
			if !e.running {
				e.Status = "pending"
				e.due = s.now()
				e.cooldown = time.Time{}
			}
			return SmartActionResult{}, nil
		}
		if request.Action == "preview" && e.Status == "ready" && e.Action != "" {
			copy := cloneSmartEntry(e).SmartSuggestion
			return SmartActionResult{Suggestion: &copy}, nil
		}
		return SmartActionResult{}, errors.New("Smart suggestion is not ready")
	}
	return SmartActionResult{}, errors.New("Smart suggestion is unavailable")
}
func (s *smartCoordinator) cancelCurrentLocked() {
	if s.cancel != nil {
		s.cancel()
	}
	s.generation++
	if s.ctx != nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
}
func smartDomain(domain string) bool {
	if !validDNSSuffix(domain) || !strings.Contains(domain, ".") {
		return false
	}
	for _, suffix := range []string{"local", "localhost", "internal", "lan", "home", "home.arpa", "invalid", "test", "onion", "alt", "arpa"} {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return false
		}
	}
	return true
}

func (s *smartCoordinator) checkNetwork(force bool) bool {
	s.networkMu.Lock()
	defer s.networkMu.Unlock()
	freshness := 5 * time.Second
	if force {
		freshness = time.Second
	}
	s.mu.Lock()
	if s.blocked {
		s.mu.Unlock()
		return false
	}
	tun := s.ownedTun
	if s.now().Sub(s.networkChecked) < freshness {
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	if tun == "" {
		tun = s.one.policy.Load().cfg.Core.Tun
	}
	current, err := s.networkSample(tun)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.networkChecked = s.now()
	if err != nil || s.network != "" && s.network != current {
		s.blocked = true
		if s.cancel != nil {
			s.cancel()
		}
		for _, e := range s.entries {
			e.Status = "expired"
			e.Action = ""
			e.due = time.Time{}
		}
	} else if s.network == "" {
		s.network = current
	}
	return !s.blocked
}

package kone

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HealthResult records one observation, rather than inferring application success
// from a successful probe of a different port or outbound.
type HealthResult struct {
	DNSCode string `json:"dns_code,omitempty"`
	Message string `json:"message,omitempty"`

	Address string `json:"address,omitempty"`

	Protocol   string    `json:"protocol"`
	Port       uint16    `json:"port"`
	Source     string    `json:"source"`
	Outbound   string    `json:"outbound"`
	Status     string    `json:"status"`
	Stage      string    `json:"stage"`
	DurationMS int64     `json:"duration_ms"`
	Time       time.Time `json:"time"`
}
type HealthTransition struct {
	Generation uint64    `json:"generation"`
	Resolution string    `json:"resolution"`
	Time       time.Time `json:"time"`
}
type HealthIncident struct {
	Transitions []HealthTransition `json:"transitions,omitempty"`

	Checking bool `json:"checking"`

	Suggestions map[uint16]string `json:"suggestions,omitempty"`
	Temporary   map[uint16]string `json:"temporary,omitempty"`
	Expires     time.Time         `json:"expires,omitempty"`

	ID         uint64         `json:"id"`
	Generation uint64         `json:"generation"`
	Domain     string         `json:"domain"`
	Scope      string         `json:"scope"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason"`
	First      time.Time      `json:"first"`
	Last       time.Time      `json:"last"`
	Count      uint64         `json:"count"`
	Results    []HealthResult `json:"results"`
	ClosedAt   time.Time      `json:"closed_at,omitempty"`
	Resolution string         `json:"resolution,omitempty"`
}
type HealthLedger struct {
	mu      sync.Mutex
	path    string
	next    uint64
	entries map[string]HealthIncident
}

// OpenHealthLedger refuses unreadable/corrupt state instead of presenting an
// empty healthy view. Unresolved summaries have no time-based eviction.
func OpenHealthLedger(path string) (*HealthLedger, error) {
	l := &HealthLedger{path: path, entries: map[string]HealthIncident{}}
	if path == "" {
		return l, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var state struct {
		Next    uint64
		Entries map[string]HealthIncident
	}
	if err = json.Unmarshal(b, &state); err != nil {
		return nil, err
	}
	if state.Entries == nil {
		return nil, errors.New("invalid connection health state")
	}
	l.next, l.entries = state.Next, state.Entries
	return l, nil
}
func healthKey(domain, scope string) string { return normalizeDomain(domain) + "\x00" + scope }
func (l *HealthLedger) persistLocked() error {
	if l.path == "" {
		return nil
	}
	b, err := json.Marshal(struct {
		Next    uint64
		Entries map[string]HealthIncident
	}{l.next, l.entries})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(l.path), ".health-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, l.path)
}
func cloneHealthIncident(e HealthIncident) HealthIncident {
	e.Results = append([]HealthResult(nil), e.Results...)
	e.Transitions = append([]HealthTransition(nil), e.Transitions...)
	e.Suggestions = maps.Clone(e.Suggestions)
	e.Temporary = maps.Clone(e.Temporary)
	return e
}
func (l *HealthLedger) Observe(domain, scope, reason string, result HealthResult) (HealthIncident, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := healthKey(domain, scope)
	old, exists := l.entries[key]
	e := cloneHealthIncident(old)
	if exists && e.Status != "attention" && !result.Time.After(e.ClosedAt) {
		return e, nil
	}
	if !exists {
		l.next++
		e = HealthIncident{ID: l.next, Domain: normalizeDomain(domain), Scope: scope, First: result.Time}
	}
	e.Generation++
	if e.Status != "attention" {
		e.Status = "attention"
		e.Resolution = ""
		e.ClosedAt = time.Time{}
	}
	e.Reason, e.Last = reason, result.Time
	e.Count++
	replaced := false
	for i, r := range e.Results {
		if r.Protocol == result.Protocol && r.Port == result.Port && r.Source == result.Source && r.Outbound == result.Outbound {
			e.Results[i] = result
			replaced = true
			break
		}
	}
	if !replaced {
		e.Results = append(e.Results, result)
	}
	l.entries[key] = e
	if err := l.persistLocked(); err != nil {
		if exists {
			l.entries[key] = old
		} else {
			delete(l.entries, key)
		}
		return HealthIncident{}, err
	}
	return cloneHealthIncident(e), nil
}

// Resolve is generation-checked so a late probe cannot close a newly reopened
// incident. Callers must establish that all outstanding fault conditions clear.
func (l *HealthLedger) Resolve(domain, scope string, generation uint64, resolution string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := healthKey(domain, scope)
	old, ok := l.entries[key]
	if !ok || old.Generation != generation {
		return errors.New("connection health evidence is stale")
	}
	e := cloneHealthIncident(old)
	e.Status = "history"
	if resolution == "automatic" {
		e.Status = "adjusted"
	}
	e.Resolution = resolution
	e.Transitions = append(e.Transitions, HealthTransition{generation, resolution, now})
	if len(e.Transitions) > 20 {
		e.Transitions = e.Transitions[len(e.Transitions)-20:]
	}
	e.ClosedAt = now
	l.entries[key] = e
	if err := l.persistLocked(); err != nil {
		l.entries[key] = old
		return err
	}
	return nil
}
func (l *HealthLedger) Snapshot(offset, limit int) ([]HealthIncident, int) {
	return l.Filtered(offset, limit, "", "")
}
func (l *HealthLedger) Filtered(offset, limit int, status, search string) ([]HealthIncident, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all := make([]HealthIncident, 0, len(l.entries))
	for _, e := range l.entries {
		if status != "" && status != "all" && e.Status != status && !(status == "history" && len(e.Transitions) > 0) {
			continue
		}
		if !strings.Contains(e.Domain, strings.ToLower(search)) {
			continue
		}
		copy := cloneHealthIncident(e)
		if status == "history" && len(copy.Transitions) > 0 {
			last := copy.Transitions[len(copy.Transitions)-1]
			copy.Status = "history"
			copy.Resolution = last.Resolution
			copy.ClosedAt = last.Time
		}
		all = append(all, copy)
	}
	sort.Slice(all, func(i, j int) bool {
		if (all[i].Status == "attention") != (all[j].Status == "attention") {
			return all[i].Status == "attention"
		}
		return all[i].ID > all[j].ID
	})
	total := len(all)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}

// Refresh merges current probe evidence without manufacturing a failure or
// erasing an outstanding business fault on another protocol/port.
func (l *HealthLedger) Refresh(domain, scope string, results []HealthResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := healthKey(domain, scope)
	old, exists := l.entries[key]
	entry := cloneHealthIncident(old)
	if !exists {
		l.next++
		entry = HealthIncident{ID: l.next, Generation: 1, Domain: normalizeDomain(domain), Scope: scope, Status: "observed", First: time.Now()}
	}
	for _, result := range results {
		if result.Source == "candidate" {
			continue
		}
		updated := false
		for i, r := range entry.Results {
			if r.Port == result.Port && r.Protocol == result.Protocol && r.Source == result.Source {
				entry.Results[i] = result
				updated = true
				break
			}
		}
		if !updated {
			entry.Results = append(entry.Results, result)
		}
	}
	entry.Last = time.Now()
	l.entries[key] = entry
	if err := l.persistLocked(); err != nil {
		if exists {
			l.entries[key] = old
		} else {
			delete(l.entries, key)
		}
		return err
	}
	return nil
}

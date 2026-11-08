package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/xjdrew/kone/pkg/kone"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var errHealthRuleConflict = errors.New("an existing manual rule conflicts with this selection")

type connectionHealthOwner interface {
	HealthData(kone.HealthQuery) (kone.HealthState, error)
	HealthAction(kone.HealthAction) (kone.HealthIncident, error)
}

func (c *Controller) healthArchivePath() string {
	return filepath.Join(c.directory, "connection-health.json")
}
func (c *Controller) archivedHealth() (kone.HealthState, error) {
	c.healthArchiveMu.Lock()
	defer c.healthArchiveMu.Unlock()
	return c.readArchivedHealth()
}
func (c *Controller) readArchivedHealth() (kone.HealthState, error) {
	state := kone.HealthState{Status: "paused", Entries: []kone.HealthIncident{}}
	data, err := os.ReadFile(c.healthArchivePath())
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(data, &state)
	state.Status = "paused"
	return state, err
}
func (c *Controller) mirrorConnectionHealth(ctx context.Context) {
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.mu.Lock()
			engine, running := c.engine, c.state == "running"
			c.mu.Unlock()
			owner, ok := engine.(connectionHealthOwner)
			if !ok || !running {
				continue
			}
			state, err := owner.HealthData(kone.HealthQuery{Limit: 100})
			if err != nil {
				continue
			}
			for offset := len(state.Entries); offset < state.Total; offset += 100 {
				next, e := owner.HealthData(kone.HealthQuery{Offset: offset, Limit: 100})
				if e != nil {
					err = e
					break
				}
				state.Entries = append(state.Entries, next.Entries...)
			}
			if err != nil {
				continue
			}
			// Acknowledgements made while paused remain authoritative for that incident
			// generation. New failures have a different generation and are not suppressed.
			archived, _ := c.archivedHealth()
			acknowledged := map[string]kone.HealthIncident{}
			for _, old := range archived.Entries {
				if old.Resolution == "user" {
					acknowledged[old.Domain+"\x00"+old.Scope] = old
				}
			}
			for i, entry := range state.Entries {
				if old, exists := acknowledged[entry.Domain+"\x00"+entry.Scope]; exists && old.Generation == entry.Generation && entry.Status == "attention" {
					if _, err := owner.HealthAction(kone.HealthAction{Action: "handled", Domain: entry.Domain, Scope: entry.Scope, Generation: entry.Generation}); err == nil {
						state.Entries[i] = old
					}
				}
			}
			_ = c.saveHealthArchive(state)
		}
	}
}
func (c *Controller) connectionHealthRoute(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	engine, running, current := c.engine, c.state == "running", cloneDocument(c.doc)
	c.mu.Unlock()
	owner, ok := engine.(connectionHealthOwner)
	if r.Method == http.MethodGet {
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if offset < 0 {
			offset = 0
		}
		if limit < 1 || limit > 100 {
			limit = 100
		}
		var state kone.HealthState
		var err error
		if ok && running {
			state, err = owner.HealthData(kone.HealthQuery{Offset: offset, Limit: limit, Status: r.URL.Query().Get("status"), Search: r.URL.Query().Get("search")})
		} else {
			state, err = c.archivedHealth()
			state.AutoEnabled = current.Config.Policy.Smart.AutoEnabled
			filtered := []kone.HealthIncident{}
			status, search := r.URL.Query().Get("status"), strings.ToLower(r.URL.Query().Get("search"))
			for _, e := range state.Entries {
				if (status == "" || status == "all" || e.Status == status || status == "history" && len(e.Transitions) > 0) && strings.Contains(e.Domain, search) {
					filtered = append(filtered, e)
				}
			}
			state.Entries = filtered
			state.Total = len(state.Entries)
			offset = min(offset, state.Total)
			state.Entries = state.Entries[offset:min(offset+limit, state.Total)]
		}
		if err != nil {
			apiError(w, 503, "health_unavailable", "Connection health state could not be read; preserve the state files")
			return
		}
		c.mu.Lock()
		archiveError := c.healthArchiveError
		c.mu.Unlock()
		if archiveError != "" {
			state.Error = archiveError
		}
		writeJSON(w, 200, state)
		return
	}
	c.actions.Lock()
	defer c.actions.Unlock()
	var action kone.HealthAction
	if err := readJSON(w, r, &action); err != nil {
		apiError(w, 400, "request", err.Error())
		return
	}
	if !ok || !running {
		if action.Action != "handled" {
			apiError(w, 409, "health_paused", "Enable proxy before checking or adjusting a target")
			return
		}
		state, err := c.archivedHealth()
		if err != nil {
			apiError(w, 503, "health_unavailable", "Health history cannot be read")
			return
		}
		found := false
		for i, e := range state.Entries {
			if e.Domain == action.Domain && e.Scope == action.Scope && e.Generation == action.Generation {
				state.Entries[i].Status = "history"
				state.Entries[i].Resolution = "user"
				state.Entries[i].ClosedAt = time.Now()
				state.Entries[i].Transitions = append(state.Entries[i].Transitions, kone.HealthTransition{Generation: e.Generation, Resolution: "user", Time: state.Entries[i].ClosedAt})
				found = true
			}
		}
		if !found {
			apiError(w, 409, "health_stale", "Health incident changed")
			return
		}
		if err = c.saveHealthArchive(state); err != nil {
			apiError(w, 500, "health_unavailable", "Health history cannot be saved")
			return
		}
		writeJSON(w, 200, state)
		return
	}
	entry, err := owner.HealthAction(action)
	if err != nil {
		apiError(w, 409, "health_stale", err.Error())
		return
	}
	if action.Action != "pin" {
		writeJSON(w, 200, entry)
		return
	}
	c.mu.Lock()
	current = cloneDocument(c.doc)
	c.mu.Unlock()
	if action.Version != current.Version {
		apiError(w, 409, "version_conflict", "Configuration changed")
		return
	}
	save, err := healthRuleSave(current, entry)
	if err != nil {
		code := "health_stale"
		if errors.Is(err, errHealthRuleConflict) {
			code = "health_conflict"
		}
		apiError(w, 409, code, err.Error())
		return
	}
	if _, err = owner.HealthAction(action); err != nil {
		apiError(w, 409, "health_stale", err.Error())
		return
	}
	saved, err := c.saveLocked(save)
	if err != nil {
		apiError(w, 409, "version_conflict", err.Error())
		return
	}
	if saved["apply_error"] == nil || saved["apply_error"] == "" {
		_, _ = owner.HealthAction(kone.HealthAction{Action: "handled", Domain: entry.Domain, Scope: entry.Scope, Generation: entry.Generation})
	}
	writeJSON(w, 200, saved)
}
func healthRuleSave(current Document, entry kone.HealthIncident) (SaveRequest, error) {
	cfg := cloneDocument(current).Config
	if len(entry.Suggestions) == 0 {
		return SaveRequest{}, errors.New("no verified scope to pin")
	}
	for port, outbound := range entry.Suggestions {
		exists := false
		for _, rule := range cfg.Rule {
			if rule.Schema == "DOMAIN" && rule.Pattern == entry.Domain && rule.Protocol == "tcp" && len(rule.Ports) == 1 && rule.Ports[0] == port {
				if rule.Outbound != outbound {
					return SaveRequest{}, errHealthRuleConflict
				}
				exists = true
			}
		}
		if exists {
			continue
		}
		schema, pattern := "DOMAIN", entry.Domain
		if ip, err := netip.ParseAddr(entry.Domain); err == nil {
			if ip.Is4() {
				schema = "IP-CIDR"
				pattern = ip.String() + "/32"
			} else {
				schema = "IP-CIDR6"
				pattern = ip.String() + "/128"
			}
		}
		rule := kone.RuleConfig{ID: "rule-health-" + strconv.FormatUint(entry.ID, 10) + "-" + strconv.Itoa(int(port)), Schema: schema, Pattern: pattern, Protocol: "tcp", Ports: []uint16{port}, Outbound: outbound, Source: "user"}
		index := len(cfg.Rule)
		if index > 0 && cfg.Rule[index-1].Schema == "FINAL" {
			index--
		}
		cfg.Rule = append(cfg.Rule, kone.RuleConfig{})
		copy(cfg.Rule[index+1:], cfg.Rule[index:])
		cfg.Rule[index] = rule
	}
	credentials := map[string]CredentialAction{}
	for _, o := range cfg.Outbounds {
		credentials[o.Name] = CredentialAction{Action: "preserve"}
	}
	return SaveRequest{BaseVersion: current.Version, Config: jsonConfig(cfg), Inbound: current.Inbound, CredentialActions: credentials}, nil
}

func (c *Controller) snapshotConnectionHealth(engine Engine) {
	owner, ok := engine.(connectionHealthOwner)
	if !ok {
		return
	}
	state, err := owner.HealthData(kone.HealthQuery{Limit: 100})
	if err != nil {
		return
	}
	for offset := len(state.Entries); offset < state.Total; offset += 100 {
		part, e := owner.HealthData(kone.HealthQuery{Offset: offset, Limit: 100})
		if e != nil {
			return
		}
		state.Entries = append(state.Entries, part.Entries...)
	}
	_ = c.saveHealthArchive(state)
}

func (c *Controller) saveHealthArchive(state kone.HealthState) error {
	c.healthArchiveMu.Lock()
	defer c.healthArchiveMu.Unlock()
	old, _ := c.readArchivedHealth()
	acknowledged := map[string]kone.HealthIncident{}
	for _, previous := range old.Entries {
		if previous.Resolution == "user" {
			acknowledged[previous.Domain+"\x00"+previous.Scope] = previous
		}
	}
	for i, e := range state.Entries {
		if previous, exists := acknowledged[e.Domain+"\x00"+e.Scope]; exists && e.Generation == previous.Generation {
			state.Entries[i].Status = previous.Status
			state.Entries[i].Resolution = previous.Resolution
			state.Entries[i].ClosedAt = previous.ClosedAt
		}
	}
	data, err := json.Marshal(state)
	if err == nil {
		previous, _ := os.ReadFile(c.healthArchivePath())
		if !bytes.Equal(previous, data) {
			err = atomicWrite(c.healthArchivePath(), data)
		}
	}
	c.mu.Lock()
	if err != nil {
		c.healthArchiveError = err.Error()
	} else {
		c.healthArchiveError = ""
	}
	c.mu.Unlock()
	return err
}

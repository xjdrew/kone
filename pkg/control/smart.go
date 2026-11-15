package control

import (
	"errors"
	"github.com/xjdrew/kone/pkg/kone"
	"net/http"
)

type smartOwner interface {
	SmartData() (kone.SmartState, error)
	SmartAction(kone.SmartAction) (kone.SmartActionResult, error)
}

func (c *Controller) smartRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		c.actions.Lock()
		defer c.actions.Unlock()
	}
	c.mu.Lock()
	engine := c.engine
	current := cloneDocument(c.doc)
	running := c.state == "running"
	c.mu.Unlock()
	owner, ok := engine.(smartOwner)
	if r.Method == http.MethodGet {
		if !ok || !running {
			writeJSON(w, 200, kone.SmartState{Enabled: current.Config.Policy.Smart.Enabled, Status: "paused", Suggestions: []kone.SmartSuggestion{}})
			return
		}
		state, err := owner.SmartData()
		if err != nil {
			apiError(w, 503, "data_unavailable", "Smart observations unavailable")
			return
		}
		writeJSON(w, 200, state)
		return
	}
	if !ok || !running {
		apiError(w, 409, "smart_stale", "Enable capture before using Smart suggestions")
		return
	}
	var request kone.SmartAction
	if err := readJSON(w, r, &request); err != nil {
		apiError(w, 400, "request", err.Error())
		return
	}
	action := request.Action
	if action == "accept" {
		request.Action = "preview"
	}
	result, err := owner.SmartAction(request)
	if err != nil {
		apiError(w, 409, "smart_stale", err.Error())
		return
	}
	if action != "accept" && action != "preview" {
		writeJSON(w, 200, result)
		return
	}
	if request.Version != current.Version || result.Suggestion == nil || result.Suggestion.ConfigVersion != current.Version {
		apiError(w, 409, "version_conflict", "Configuration changed; refresh the suggestion")
		return
	}
	save, rule, err := prepareSmartRule(current, *result.Suggestion)
	if err != nil {
		apiError(w, 409, "smart_stale", err.Error())
		return
	}
	if action == "preview" {
		validation, err := c.Validate(save)
		if err != nil {
			apiError(w, 400, "request", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"suggestion": result.Suggestion, "rule": rule, "validation": validation})
		return
	}
	// Recheck evidence immediately before the versioned transaction. No browser
	// supplied rule, outbound or target is trusted as a substitute for evidence.
	if _, err = owner.SmartAction(request); err != nil {
		apiError(w, 409, "smart_stale", err.Error())
		return
	}
	saved, err := c.saveLocked(save)
	if err != nil {
		code := "request"
		status := 400
		if errors.Is(err, ErrConflict) {
			code = "version_conflict"
			status = 409
		}
		apiError(w, status, code, err.Error())
		return
	}
	writeJSON(w, 200, saved)
}
func prepareSmartRule(current Document, suggestion kone.SmartSuggestion) (SaveRequest, kone.RuleConfig, error) {
	cfg := cloneDocument(current).Config
	if cfg.Policy.RuleVersion != 2 || !cfg.Policy.Smart.Enabled || suggestion.Port != 443 || suggestion.Protocol != "tcp+tls" {
		return SaveRequest{}, kone.RuleConfig{}, errors.New("Smart evidence does not match enabled policy")
	}
	outbound := kone.BuiltinDirect
	if suggestion.Action == "proxy" {
		outbound = ""
		for _, out := range cfg.Outbounds {
			if out.ID == suggestion.OutboundID && out.IsEnabled() {
				outbound = out.Name
			}
		}
		if outbound == "" {
			return SaveRequest{}, kone.RuleConfig{}, errors.New("suggested outbound no longer exists")
		}
	} else if suggestion.Action != "direct" {
		return SaveRequest{}, kone.RuleConfig{}, errors.New("invalid suggestion action")
	}
	rule := kone.RuleConfig{ID: "rule-smart-" + suggestion.ID, Source: "smart", Schema: "DOMAIN", Pattern: suggestion.Domain, Protocol: "tcp", Ports: []uint16{443}, Outbound: outbound}
	index := len(cfg.Rule)
	if index > 0 && cfg.Rule[index-1].Schema == "FINAL" {
		index--
	}
	cfg.Rule = append(cfg.Rule, kone.RuleConfig{})
	copy(cfg.Rule[index+1:], cfg.Rule[index:])
	cfg.Rule[index] = rule
	credentials := map[string]CredentialAction{}
	for _, out := range cfg.Outbounds {
		credentials[out.Name] = CredentialAction{Action: "preserve"}
	}
	return SaveRequest{BaseVersion: current.Version, Config: jsonConfig(cfg), Inbound: current.Inbound, CredentialActions: credentials}, rule, nil
}

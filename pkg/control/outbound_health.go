package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

const outboundHealthTTL = time.Minute
const maxOutboundHealthEntries = 256

type OutboundHealth struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Status           string                   `json:"status"`
	Stage            string                   `json:"stage"`
	Message          string                   `json:"message"`
	Target           string                   `json:"target"`
	TLS              bool                     `json:"tls"`
	CheckedAt        *time.Time               `json:"checked_at,omitempty"`
	ExpiresAt        *time.Time               `json:"expires_at,omitempty"`
	Stale            bool                     `json:"stale"`
	OperationID      string                   `json:"operation_id,omitempty"`
	ConfigurationID  string                   `json:"configuration_id"`
	DurationMS       int64                    `json:"duration_ms"`
	ConfigVersion    uint64                   `json:"config_version"`
	Scope            string                   `json:"scope"`
	ConnectLatencyMS *int64                   `json:"connect_latency_ms,omitempty"`
	Host             kone.DiagnosticHost      `json:"host"`
	Protocols        kone.DiagnosticProtocols `json:"protocols"`
	Progress         kone.DiagnosticProgress  `json:"progress"`
}
type outboundHealthEntry struct {
	status     OutboundHealth
	generation uint64
	updated    time.Time
}
type outboundHealthStore struct {
	entries  map[string]*outboundHealthEntry
	sequence uint64
}
type OutboundTestDraft struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Enabled     *bool  `json:"enabled,omitempty"`
	UDPFallback string `json:"udp-fallback,omitempty"`
}
type OutboundTestRequest struct {
	BaseVersion      uint64             `json:"base_version"`
	OutboundID       string             `json:"outbound_id,omitempty"`
	Draft            *OutboundTestDraft `json:"draft,omitempty"`
	CredentialAction CredentialAction   `json:"credential_action,omitempty"`
	Target           *string            `json:"target,omitempty"`
	TLS              *bool              `json:"tls,omitempty"`
}

func outboundIdentity(cfg *kone.KoneConfig, outbound kone.OutboundConfig) string {
	// Credential-bearing hashes stay private; clients receive a random token,
	// so the health API cannot become an offline password guessing oracle.
	data, _ := json.Marshal(struct {
		URL     string
		Enabled bool
		Core    kone.CoreConfig
		DNS     kone.DNSConfig
	}{outbound.URL, outbound.Enabled == nil || *outbound.Enabled, cfg.Core, cfg.DNS})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func (c *Controller) healthEntryLocked(identity string, now time.Time) *outboundHealthEntry {
	if c.health == nil {
		c.health = &outboundHealthStore{entries: map[string]*outboundHealthEntry{}}
	}
	if entry := c.health.entries[identity]; entry != nil {
		return entry
	}
	if len(c.health.entries) >= maxOutboundHealthEntries {
		oldest := ""
		var when time.Time
		for key, entry := range c.health.entries {
			if oldest == "" || entry.updated.Before(when) {
				oldest, when = key, entry.updated
			}
		}
		delete(c.health.entries, oldest)
	}
	entry := &outboundHealthEntry{status: OutboundHealth{
		Status: "unknown", Stage: "not_tested", Message: "Not tested; run an explicit outbound test",
		ConfigurationID: randomID("health"), Scope: "explicit TCP connection test; UDP and application behavior are not tested",
		Host: kone.DiagnosticHost{Status: "unknown", Message: "Endpoint connection was not tested"}, Protocols: kone.DiagnosticProtocolEvidence(""),
	}, updated: now}
	c.health.entries[identity] = entry
	return entry
}

func (c *Controller) reserveOutboundTestLocked(version uint64, identity string) (*outboundHealthStore, uint64, error) {
	// Preparing a credential-bearing draft happens outside the controller lock.
	// A reset or save in that interval must invalidate the old configuration
	// before it can recreate health state or start a diagnostic connection.
	if c.doc.Version != version {
		return nil, 0, ErrConflict
	}
	c.healthEntryLocked(identity, c.now())
	c.health.sequence++
	return c.health, c.health.sequence, nil
}

func (c *Controller) outboundStatuses(cfg *kone.KoneConfig) []OutboundHealth {
	now := c.now()
	result := make([]OutboundHealth, 0, len(cfg.Outbounds))
	for _, outbound := range cfg.Outbounds {
		identity := outboundIdentity(cfg, outbound)
		c.mu.Lock()
		status := c.healthEntryLocked(identity, now).status
		c.mu.Unlock()
		status.ID, status.Name = outbound.ID, outbound.Name
		if outbound.Enabled != nil && !*outbound.Enabled {
			status.Status, status.Stage, status.Message = "unknown", "disabled", "This outbound is disabled"
		}
		if status.Status != "testing" && status.ExpiresAt != nil && !now.Before(*status.ExpiresAt) {
			status.Status, status.Stale = "unknown", true
			status.Message = "The previous test expired; test this outbound again"
		}
		result = append(result, status)
	}
	return result
}
func (c *Controller) outboundHealthRoute(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		apiError(w, 400, "request", "Outbound health does not accept query parameters")
		return
	}
	c.mu.Lock()
	cfg := cloneDocument(c.doc).Config
	c.mu.Unlock()
	writeJSON(w, 200, map[string]any{"statuses": c.outboundStatuses(cfg), "time": c.now()})
}

func prepareOutboundTest(request OutboundTestRequest, current Document) (Document, kone.OutboundConfig, error) {
	if request.BaseVersion != current.Version {
		return Document{}, kone.OutboundConfig{}, ErrConflict
	}
	var old *kone.OutboundConfig
	id := request.OutboundID
	if request.Draft != nil && request.Draft.ID != "" {
		if id != "" && id != request.Draft.ID {
			return Document{}, kone.OutboundConfig{}, errors.New("outbound identity does not match the draft")
		}
		id = request.Draft.ID
	}
	for i := range current.Config.Outbounds {
		if current.Config.Outbounds[i].ID == id && id != "" {
			old = &current.Config.Outbounds[i]
			break
		}
	}
	if request.Draft == nil {
		if old == nil {
			return Document{}, kone.OutboundConfig{}, errors.New("select a saved outbound or provide a draft")
		}
		if request.CredentialAction.Action != "" {
			return Document{}, kone.OutboundConfig{}, errors.New("credential edits require an outbound draft")
		}
		if old.Enabled != nil && !*old.Enabled {
			return Document{}, kone.OutboundConfig{}, errors.New("enable this outbound before testing")
		}
		return current, *old, nil
	}
	if request.OutboundID != "" && old == nil {
		return Document{}, kone.OutboundConfig{}, errors.New("saved outbound no longer exists")
	}
	draft := *request.Draft
	if draft.Enabled == nil && old != nil {
		draft.Enabled = old.Enabled
	}
	configuration := jsonConfig(current.Config)
	value := map[string]any{"name": draft.Name, "url": draft.URL}
	if draft.ID != "" {
		value["id"] = draft.ID
	}
	if draft.Enabled != nil {
		value["enabled"] = *draft.Enabled
	}
	if draft.UDPFallback != "" {
		value["udp-fallback"] = draft.UDPFallback
	}
	configuration["outbounds"] = []any{value}
	configuration["rules"] = []any{}
	action := request.CredentialAction
	if old != nil {
		if action.OriginalName != "" && action.OriginalName != old.Name {
			return Document{}, kone.OutboundConfig{}, errors.New("credential identity does not match the saved outbound")
		}
		action.OriginalName = old.Name
	}
	next, err := prepareDocument(SaveRequest{BaseVersion: current.Version, Config: configuration, Inbound: current.Inbound, DirectOnlyConfirmed: &current.DirectOnlyConfirmed, CredentialActions: map[string]CredentialAction{draft.Name: action}}, current)
	if err != nil {
		return Document{}, kone.OutboundConfig{}, err
	}
	outbound := next.Config.Outbounds[0]
	if outbound.Enabled != nil && !*outbound.Enabled {
		return Document{}, kone.OutboundConfig{}, errors.New("enable this draft outbound before testing")
	}
	return next, outbound, nil
}
func outboundTestError(err error, request OutboundTestRequest, cfg *kone.KoneConfig) error {
	message := safeMessage(err, cfg)
	secrets := []string{request.CredentialAction.Username, request.CredentialAction.Password}
	if request.Draft != nil {
		if endpoint, e := url.Parse(request.Draft.URL); e == nil && endpoint.User != nil {
			password, _ := endpoint.User.Password()
			secrets = append(secrets, endpoint.User.Username(), password)
		}
	}
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "REDACTED")
		}
	}
	return errors.New(logstore.RedactText(message))
}
func (c *Controller) testOutboundRoute(w http.ResponseWriter, r *http.Request, key string) {
	var request OutboundTestRequest
	if readJSON(w, r, &request) != nil {
		apiError(w, 400, "request", "Invalid outbound test request")
		return
	}
	operation, err := c.TestOutbound(request, key)
	if err != nil {
		status := 400
		if errors.Is(err, ErrConflict) {
			status = 409
		}
		apiError(w, status, "outbound_test", err.Error())
		return
	}
	writeOperation(w, operation)
}

func (c *Controller) TestOutbound(request OutboundTestRequest, key string) (Operation, error) {
	target := "example.com:443"
	if request.Target != nil {
		target = *request.Target
	}
	if err := validTarget(target); err != nil {
		return Operation{}, err
	}
	withTLS := request.TLS == nil || *request.TLS
	c.mu.Lock()
	current := cloneDocument(c.doc)
	engine := c.engine
	source := c.dataSource
	c.mu.Unlock()
	prepared, outbound, err := prepareOutboundTest(request, current)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return Operation{}, err
		}
		return Operation{}, outboundTestError(err, request, current.Config)
	}
	identity := outboundIdentity(current.Config, outbound)
	if key != "" {
		key += "\x00" + identity + "\x00" + target
		if withTLS {
			key += "\x00tls"
		}
	}
	c.mu.Lock()
	healthStore, generation, err := c.reserveOutboundTestLocked(current.Version, identity)
	c.mu.Unlock()
	if err != nil {
		return Operation{}, err
	}
	gate := make(chan struct{})
	operationID := ""
	operation := c.beginOperation("outbound_test", key, 12*time.Second, func(ctx context.Context) (any, error) {
		<-gate
		now := c.now()
		c.mu.Lock()
		if c.health != healthStore {
			c.mu.Unlock()
			return OutboundHealth{ID: outbound.ID, Name: outbound.Name, Status: "unknown", Stage: "canceled", Message: "Configuration reset canceled this outbound test"}, context.Canceled
		}
		entry := c.healthEntryLocked(identity, now)
		status := entry.status
		status.ID, status.Name = outbound.ID, outbound.Name
		status.Status, status.Stage, status.Message = "testing", "connect", "Testing the selected proxy protocol and target"
		status.Target, status.TLS, status.OperationID = target, withTLS, operationID
		status.ConfigVersion = current.Version
		status.Stale = false
		status.CheckedAt, status.ExpiresAt, status.ConnectLatencyMS = nil, nil, nil
		status.DurationMS = 0
		status.Host = kone.DiagnosticHost{Status: "testing", Message: "Waiting for the endpoint connection test"}
		status.Protocols = kone.DiagnosticProtocolEvidence("")
		status.Protocols.TCP.Status = "testing"
		status.Progress = kone.DiagnosticProgress{Stage: "connect", Total: 2}
		if withTLS {
			status.Progress.Total++
		}
		if generation >= entry.generation {
			entry.status, entry.generation, entry.updated = status, generation, now
		}
		c.mu.Unlock()
		c.publishOutboundProgress(identity, generation, operationID, status)
		if err := ctx.Err(); err != nil {
			status.Status, status.Stage, status.Message = "unknown", "canceled", "Outbound test canceled or timed out"
			status = c.finishOutboundTest(identity, generation, status)
			return status, err
		}
		select {
		case c.probeSlots <- struct{}{}:
			defer func() { <-c.probeSlots }()
		default:
			status.Status, status.Stage, status.Message = "unknown", "capacity", "Diagnostic concurrency limit reached; retry later"
			status = c.finishOutboundTest(identity, generation, status)
			return status, errors.New(status.Message)
		}
		probeCfg := engineConfig(prepared)
		ctx = kone.WithDiagnosticProgress(ctx, func(result kone.DiagnosticResult) {
			if result.Progress.Stage == "complete" {
				return
			}
			status.ConnectLatencyMS, status.Host, status.Protocols, status.Progress = result.ConnectLatencyMS, result.Host, result.Protocols, result.Progress
			status.Stage = result.Progress.Stage
			if status.Stage == "" {
				status.Stage = result.Stage
			}
			c.publishOutboundProgress(identity, generation, operationID, status)
		})
		var result ProbeResult
		var probeErr error
		if request.Draft == nil {
			if active, ok := engine.(interface {
				ProbeDiagnosticVersion(context.Context, string, string, bool, uint64) (kone.DiagnosticResult, error)
			}); ok {
				result, probeErr = active.ProbeDiagnosticVersion(ctx, outbound.Name, target, withTLS, current.Version)
			} else {
				result = c.probe(ctx, probeCfg, outbound.Name, target, withTLS)
			}
		} else {
			// Preserve the active resolver snapshot while testing an unapplied
			// endpoint: system DNS may currently point back into KONE.
			if engine != nil {
				if source == nil {
					probeErr = errors.New("capture DNS context is unavailable; pause capture before testing the draft")
				} else {
					var dns kone.DNSRuntimeStatus
					dns, _, probeErr = source.DNSData()
					if probeErr == nil && len(dns.Servers) == 0 {
						probeErr = errors.New("capture DNS context is unavailable; pause capture before testing the draft")
					}
					if probeErr == nil {
						probeCfg.DNS.Servers = dns.Servers
						probeCfg.DNS.Rules = dns.Rules
						probeCfg.DNS.System = false
						probeCfg.DNS.SystemContext.UseTCP = dns.UpstreamTCP
					}
				}
			}
			if probeErr == nil {
				result = c.probe(ctx, probeCfg, outbound.Name, target, withTLS)
			}
		}
		checked := c.now()
		expires := checked.Add(outboundHealthTTL)
		status.CheckedAt, status.ExpiresAt = &checked, &expires
		status.DurationMS = result.DurationMS
		status.ConnectLatencyMS, status.Host, status.Protocols, status.Progress = result.ConnectLatencyMS, result.Host, result.Protocols, result.Progress
		if status.Host.Status == "" {
			status.Host = kone.DiagnosticHost{Status: "unknown", Message: "The probe did not report endpoint connection evidence"}
		}
		if status.Protocols.TCP.Status == "" {
			status.Protocols = kone.DiagnosticProtocolEvidence("")
		}
		status.Progress.Stage = "complete"
		if status.Progress.Total == 0 {
			status.Progress.Total = 2
			if withTLS {
				status.Progress.Total++
			}
		}
		status.Stage = result.Stage
		if status.Stage == "" {
			status.Stage = "connect"
		}
		status.Message = logstore.RedactText(safeMessage(errors.New(result.Message), probeCfg))
		switch result.Status {
		case "reachable":
			status.Status = "healthy"
		case "failed":
			status.Status = "unhealthy"
		default:
			status.Status = "unknown"
		}
		if probeErr != nil {
			probeErr = outboundTestError(probeErr, request, probeCfg)
			status.Status, status.Stage, status.Message = "unknown", "context", probeErr.Error()
		}
		if err := ctx.Err(); err != nil {
			status.Status, status.Stage, status.Message = "unknown", "canceled", "Outbound test canceled or timed out"
			status = c.finishOutboundTest(identity, generation, status)
			return status, err
		}
		status = c.finishOutboundTest(identity, generation, status)
		return status, probeErr
	})
	operationID = operation.ID
	close(gate)
	return operation, nil
}
func (c *Controller) finishOutboundTest(identity string, generation uint64, status OutboundHealth) OutboundHealth {
	status.Progress.Stage = "complete"
	if status.Host.Status == "testing" {
		status.Host.Status, status.Host.Message = "unknown", "The endpoint connection test did not finish"
	}
	for _, check := range []*kone.DiagnosticCheck{&status.Protocols.TCP, &status.Protocols.TLS} {
		if check.Status == "testing" {
			check.Status, check.Tested, check.Message = "unknown", false, "The probe did not finish"
		}
	}
	level := slog.LevelInfo
	if status.Status != "healthy" {
		level = slog.LevelWarn
	}
	c.logEvent(level, "Outbound connectivity test completed", slog.String("stage", status.Stage), slog.String("outbound_id", status.ID), slog.String("operation_id", status.OperationID), slog.String("status", status.Status), slog.Int64("duration_ms", status.DurationMS))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.health != nil {
		if entry := c.health.entries[identity]; entry != nil && entry.generation == generation && entry.status.ConfigurationID == status.ConfigurationID {
			entry.status, entry.updated = status, c.now()
		}
	}
	return status
}

func (c *Controller) publishOutboundProgress(identity string, generation uint64, operationID string, status OutboundHealth) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Values contain no mutable maps/slices. Published snapshots remain stable
	// while a later stage is produced or serialized by concurrent HTTP readers.
	if c.health != nil {
		if entry := c.health.entries[identity]; entry != nil && entry.generation == generation && entry.status.ConfigurationID == status.ConfigurationID {
			entry.status, entry.updated = status, c.now()
		}
	}
	if operation := c.operations[operationID]; operation != nil && operation.Status == "running" {
		operation.Stage, operation.Result = status.Stage, status
	}
	c.logEvent(slog.LevelInfo, "Outbound connectivity test progressed", slog.String("stage", status.Stage), slog.String("outbound_id", status.ID), slog.String("operation_id", operationID), slog.String("status", status.Status))
}

func (c *Controller) outboundReadiness(cfg *kone.KoneConfig) []ReadinessCheck {
	used := map[string]bool{}
	for _, rule := range cfg.Rule {
		if rule.ExpiresAt != "" {
			if expiry, err := time.Parse(time.RFC3339, rule.ExpiresAt); err == nil && !expiry.After(c.now()) {
				continue
			}
		}
		used[rule.Outbound] = true
	}
	checks := []ReadinessCheck{}
	for i, status := range c.outboundStatuses(cfg) {
		outbound := cfg.Outbounds[i]
		if !used[outbound.Name] || outbound.Enabled != nil && !*outbound.Enabled {
			continue
		}
		check := ReadinessCheck{ID: "outbound_health_" + outbound.ID, Code: "outbound_health", Status: "warning", Severity: "warning", Message: "This rule-selected outbound has no current successful test; testing is recommended", Page: "outbounds", Field: "outbounds." + outbound.ID, Action: "test_outbound"}
		if status.Status == "healthy" {
			check.Status, check.Severity, check.Message = "ready", "info", "The selected outbound passed a recent explicit TCP test"
		}
		if status.Status == "unhealthy" {
			check.Status = "error"
			check.Message = "The latest outbound test failed; fix it or explicitly continue: " + status.Message
		}
		if status.Status == "testing" {
			check.Message = "An explicit outbound test is still running"
		}
		checks = append(checks, check)
	}
	return checks
}

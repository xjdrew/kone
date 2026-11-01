package control

import (
	"context"
	"strings"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
)

type ReadinessCheck struct {
	ID       string `json:"id"`
	Code     string `json:"code"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Page     string `json:"page"`
	Field    string `json:"field,omitempty"`
	Action   string `json:"action,omitempty"`
}

type ReadinessReport struct {
	Ready               bool             `json:"ready"`
	SavedVersion        uint64           `json:"saved_version"`
	DirectOnly          bool             `json:"direct_only"`
	DirectOnlyConfirmed bool             `json:"direct_only_confirmed"`
	Checks              []ReadinessCheck `json:"checks"`
	Blockers            []ReadinessCheck `json:"blockers"`
	Warnings            []ReadinessCheck `json:"warnings"`
	Changes             []string         `json:"changes"`
}

func directOnly(cfg *kone.KoneConfig) bool {
	for _, rule := range cfg.Rule {
		if rule.ExpiresAt != "" {
			if expiry, err := time.Parse(time.RFC3339, rule.ExpiresAt); err == nil && !expiry.After(time.Now()) {
				continue
			}
		}
		if rule.Outbound != kone.BuiltinDirect && rule.Outbound != kone.BuiltinReject {
			return false
		}
	}
	return true
}

func (c *Controller) Readiness(ctx context.Context) ReadinessReport {
	c.mu.Lock()
	doc, state, configError := cloneDocument(c.doc), c.state, c.configError
	c.mu.Unlock()
	return c.readiness(ctx, doc, state, configError)
}

func (c *Controller) readiness(ctx context.Context, doc Document, state, configError string) ReadinessReport {
	report := ReadinessReport{Ready: true, SavedVersion: doc.Version, DirectOnly: directOnly(doc.Config), DirectOnlyConfirmed: doc.DirectOnlyConfirmed, Checks: []ReadinessCheck{}, Blockers: []ReadinessCheck{}, Warnings: []ReadinessCheck{}, Changes: []string{}}
	add := func(check ReadinessCheck) {
		report.Checks = append(report.Checks, check)
		if check.Severity == "error" {
			report.Ready = false
			report.Blockers = append(report.Blockers, check)
		}
		if check.Severity == "warning" {
			report.Warnings = append(report.Warnings, check)
		}
	}
	if !doc.Inbound.Enabled {
		add(ReadinessCheck{"inbound_disabled", "inbound_disabled", "error", "error", "enable the TUN inbound before starting capture", "inbounds", "inbound.enabled", "enable_inbound"})
	}
	if doc.Inbound.Enabled {
		add(ReadinessCheck{"inbound", "inbound", "ready", "info", "The configured TUN inbound is enabled; capture still starts only on explicit request", "inbounds", "inbound.enabled", "edit_inbound"})
	}
	if len(doc.Config.DNS.Servers) == 0 {
		add(ReadinessCheck{"dns_source", "dns_source", "ready", "info", "Resolve through the system's current DNS configuration discovered at capture start; no public DNS fallback", "dns", "dns.servers", "edit_dns"})
	}
	if !doc.Config.Core.AutoRoute && !doc.Config.Core.AutoRoute6 {
		add(ReadinessCheck{"capture_scope", "capture_scope", "warning", "warning", "Selective capture covers Fake-IP and explicit CIDR routes; ordinary direct traffic can remain outside KONE", "inbounds", "core.auto-route", "edit_inbound"})
	}
	if configError != "" {
		add(ReadinessCheck{"configuration", "configuration", "error", "error", configError, "settings", "config", "repair_configuration"})
	}
	if state == "recovery_required" || state == "recovery_failed" {
		add(ReadinessCheck{"recovery", "recovery", "error", "error", "Inspect and repair the previous capture before enabling", "settings", "recovery", "inspect_recovery"})
	}
	if report.DirectOnly {
		check := ReadinessCheck{"direct_only", "direct_only", "warning", "warning", "Current rules use no proxy outbound. Capture will only use direct/reject policies; adding a proxy alone does not change these rules.", "outbounds", "rules", "configure_rules"}
		if !doc.DirectOnlyConfirmed {
			check = ReadinessCheck{"direct_only_confirmation", "direct_only_confirmation", "error", "error", "Confirm direct-only capture explicitly, or select a proxy outbound in the rules", "outbounds", "direct_only_confirmed", "confirm_direct"}
		}
		add(check)
	}
	for _, outbound := range doc.Config.Outbounds {
		if outbound.Enabled == nil || *outbound.Enabled {
			continue
		}
		for _, rule := range doc.Config.Rule {
			if rule.Outbound == outbound.Name {
				add(ReadinessCheck{"outbound_disabled_" + outbound.ID, "outbound_disabled", "warning", "warning", "A rule-selected proxy is disabled; its new connections will be rejected, not sent directly", "outbounds", "outbounds." + outbound.ID, "edit_outbound"})
				break
			}
		}
	}
	if configError == "" && state != "running" && state != "starting" && state != "pausing" {
		preflight := c.preflight(ctx, engineConfig(doc))
		if preflight.Changes != nil {
			report.Changes = preflight.Changes
		}
		errors := 0
		for _, issue := range preflight.Issues {
			page, field, action := "inbounds", "core", "edit_inbound"
			if strings.Contains(issue.Code, "dns") {
				page, field, action = "dns", "dns", "edit_dns"
			}
			if issue.Code == "privileges" {
				page, field, action = "settings", "privileges", "authorize"
			}
			status := "ready"
			if issue.Severity == "error" {
				status = "error"
				errors++
			}
			if issue.Severity == "warning" {
				status = "warning"
			}
			add(ReadinessCheck{"preflight_" + issue.Code, issue.Code, status, issue.Severity, issue.Message, page, field, action})
		}
		if !preflight.Ready && errors == 0 {
			add(ReadinessCheck{"preflight", "preflight", "error", "error", "Preflight failed; review the capture environment before enabling", "inbounds", "core", "preflight"})
		}
	}
	for _, check := range c.outboundReadiness(doc.Config) {
		add(check)
	}
	return report
}

package kone

import (
	"context"
	"net/url"
	"time"
)

type DiagnosticCheck struct {
	Status   string `json:"status"`
	Tested   bool   `json:"tested"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}

type DiagnosticHost struct {
	Address string `json:"address"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type DiagnosticProtocols struct {
	TCP DiagnosticCheck `json:"tcp"`
	TLS DiagnosticCheck `json:"tls"`
	UDP DiagnosticCheck `json:"udp"`
}

type DiagnosticProgress struct {
	Stage     string `json:"stage"`
	Completed int    `json:"completed"`
	Total     int    `json:"total"`
}

type diagnosticProgressKey struct{}
type diagnosticTransportKey struct{}
type diagnosticTransportObserver func(string, time.Duration, error)

// WithDiagnosticProgress reports actual milestones of this explicit probe.
// Callbacks run synchronously and receive value snapshots without credentials.
func WithDiagnosticProgress(ctx context.Context, update func(DiagnosticResult)) context.Context {
	return context.WithValue(ctx, diagnosticProgressKey{}, update)
}

func reportDiagnosticProgress(ctx context.Context, result DiagnosticResult) {
	ReportDiagnosticProgress(ctx, result)
}

// ReportDiagnosticProgress lets the privilege-separated transport forward the
// same factual milestones as a local probe without exposing credentials.
func ReportDiagnosticProgress(ctx context.Context, result DiagnosticResult) {
	if update, ok := ctx.Value(diagnosticProgressKey{}).(func(DiagnosticResult)); ok && update != nil {
		update(result)
	}
}

// DiagnosticProtocolEvidence reports implementation limits separately from
// measurements. UDP support is never inferred from a successful TCP test.
func DiagnosticProtocolEvidence(endpoint string) DiagnosticProtocols {
	unknown := DiagnosticCheck{Status: "unknown", Message: "Not tested"}
	checks := DiagnosticProtocols{TCP: unknown, TLS: unknown, UDP: unknown}
	if parsed, err := url.Parse(endpoint); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		checks.UDP = DiagnosticCheck{Status: "unsupported", Evidence: "protocol", Message: "This HTTP CONNECT implementation does not transport UDP; no UDP packets were sent"}
	} else {
		checks.UDP.Message = "No UDP round trip was performed; TCP success does not prove UDP support"
	}
	return checks
}

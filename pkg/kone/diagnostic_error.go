package kone

import (
	"errors"

	"github.com/xjdrew/kone/pkg/proxy"
)

type DiagnosticError struct {
	Stage string
	Err   error
}

func (e *DiagnosticError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}
func (e *DiagnosticError) Unwrap() error { return e.Err }
func DiagnosticStage(err error) string {
	var diagnostic *DiagnosticError
	if errors.As(err, &diagnostic) {
		return diagnostic.Stage
	}
	return proxy.ErrorStage(err)
}
func diagnosticError(stage string, err error) error {
	if err == nil {
		return nil
	}
	if existing := DiagnosticStage(err); existing != "" {
		stage = existing
	}
	return &DiagnosticError{Stage: stage, Err: err}
}

type DiagnosticTCPInfo struct {
	Stage              string `json:"stage"`
	TargetAcknowledged bool   `json:"target_acknowledged"`
	Scheme             string `json:"scheme"`
	PeerKind           string `json:"peer_kind"`
}

// DiagnosticTCP identifies what a successful socket/protocol setup proves.
// A Shadowsocks AEAD stream has no target success acknowledgement; a verified
// target TLS handshake is needed before claiming that target was reached.
func (one *One) DiagnosticTCP(outbound string) DiagnosticTCPInfo {
	return diagnosticTCP(one.policy.Load(), outbound)
}
func diagnosticTCP(snapshot *runtimeSnapshot, outbound string) DiagnosticTCPInfo {
	if snapshot == nil {
		return DiagnosticTCPInfo{Stage: "configuration", PeerKind: "unknown"}
	}
	entry, ok := snapshot.outbounds.entries[outbound]
	if !ok {
		return DiagnosticTCPInfo{Stage: "configuration", PeerKind: "unknown"}
	}
	if entry.disabled {
		return DiagnosticTCPInfo{Stage: "policy", PeerKind: "none", Scheme: "disabled"}
	}
	switch entry.kind {
	case OutboundDirect:
		return DiagnosticTCPInfo{Stage: "connect", TargetAcknowledged: true, Scheme: "direct", PeerKind: "target_endpoint"}
	case OutboundReject:
		return DiagnosticTCPInfo{Stage: "policy", Scheme: "reject", PeerKind: "none"}
	case OutboundProxy:
		confirmed := entry.proxy.TargetAcknowledged()
		stage := proxy.StageHandshake
		if !confirmed {
			stage = proxy.StageTransport
		}
		return DiagnosticTCPInfo{Stage: stage, TargetAcknowledged: confirmed, Scheme: entry.proxy.Url.Scheme, PeerKind: "proxy_endpoint"}
	}
	return DiagnosticTCPInfo{Stage: "configuration", PeerKind: "unknown"}
}

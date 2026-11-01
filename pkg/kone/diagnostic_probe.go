package kone

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type DiagnosticResult struct {
	Target        string    `json:"target"`
	Outbound      string    `json:"outbound"`
	Protocol      string    `json:"protocol"`
	Stage         string    `json:"stage"`
	Status        string    `json:"status"`
	Message       string    `json:"message,omitempty"`
	RemoteAddress string    `json:"remote_address,omitempty"`
	PeerKind      string    `json:"peer_kind,omitempty"`
	ConfigVersion uint64    `json:"config_version"`
	DNSPath       string    `json:"dns_path,omitempty"`
	DurationMS    int64     `json:"duration_ms"`
	Time          time.Time `json:"time"`
	Expires       time.Time `json:"expires"`
	Scope         string    `json:"scope"`
	DNSName       string    `json:"dns_name,omitempty"`
	DNSType       string    `json:"dns_type,omitempty"`
	DNSRCode      string    `json:"dns_rcode,omitempty"`
	DNSTruncated  bool      `json:"dns_truncated,omitempty"`
}

func ValidateDiagnosticTarget(target string) error {
	if len(target) > 320 || strings.ContainsAny(target, "/\\?#@\x00\r\n\t ") {
		return errors.New("target must be a hostname or IP with an explicit port")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return errors.New("target must be host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("invalid target port")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.IsUnspecified() || address.IsMulticast() {
			return errors.New("target cannot be unspecified or multicast")
		}
	} else {
		if len(host) > 253 {
			return errors.New("invalid target hostname")
		}
		for _, value := range host {
			if value > 127 || !(value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '.' || value == '-' || value == '_') {
				return errors.New("invalid target hostname")
			}
		}
	}
	return nil
}

func diagnosticMessage(err error, cfg *KoneConfig) string {
	message := safeTrafficError(err)
	if cfg != nil {
		for _, outbound := range cfg.Outbounds {
			u, err := url.Parse(outbound.URL)
			if err == nil && u.User != nil {
				if password, ok := u.User.Password(); ok && password != "" {
					message = strings.ReplaceAll(message, password, "REDACTED")
				}
				if user := u.User.Username(); user != "" {
					message = strings.ReplaceAll(message, user, "REDACTED")
				}
			}
		}
	}
	return message
}

func diagnosticVirtualAddress(snapshot *runtimeSnapshot, address netip.Addr) bool {
	address = address.Unmap()
	for _, network := range []string{snapshot.cfg.Core.Network, snapshot.cfg.Core.IPv6Network} {
		if prefix, err := netip.ParsePrefix(network); err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

// ProbeDiagnostic reuses the running engine's pinned resolver and outbound
// binding. It never creates an engine or re-reads a DNS environment that KONE
// may currently be guiding, and sends no HTTP/application request.
func (one *One) ProbeDiagnostic(parent context.Context, outbound, target string, withTLS bool) (result DiagnosticResult, err error) {
	return one.ProbeDiagnosticVersion(parent, outbound, target, withTLS, 0)
}

func (one *One) ProbeDiagnosticVersion(parent context.Context, outbound, target string, withTLS bool, expectedVersion uint64) (result DiagnosticResult, err error) {
	start := time.Now()
	result = DiagnosticResult{Target: target, Outbound: outbound, Protocol: "tcp", Stage: "configuration", Status: "failed", Time: start, Expires: start.Add(5 * time.Minute), Scope: "diagnostic; not application traffic"}
	defer func() { result.DurationMS = time.Since(start).Milliseconds() }()
	if err := ValidateDiagnosticTarget(target); err != nil {
		result.Message = err.Error()
		return result, nil
	}
	snapshot := one.policy.Load()
	if snapshot == nil {
		return result, errors.New("engine policy is unavailable")
	}
	result.ConfigVersion = snapshot.configurationVersion()
	if expectedVersion != 0 && expectedVersion != result.ConfigVersion {
		result.Status = "not_applied"
		result.Message = "The saved configuration has not been applied to this running engine"
		return result, nil
	}
	one.mu.Lock()
	closed, started, runContext := one.closed, one.started, one.runContext
	one.mu.Unlock()
	if closed {
		return result, errors.New("engine is stopping or stopped")
	}
	if started {
		select {
		case <-one.ready:
		default:
			return result, errors.New("engine is not ready for diagnostics")
		}
	}
	info := diagnosticTCP(snapshot, outbound)
	result.Stage, result.PeerKind = info.Stage, info.PeerKind
	host, _, _ := net.SplitHostPort(target)
	if info.Stage == "policy" || info.Stage == "configuration" {
		result.DNSPath = "not_attempted"
	} else if _, err := netip.ParseAddr(host); err == nil {
		result.DNSPath = "literal_ip"
	} else if info.Scheme == "direct" {
		result.DNSPath = "engine_dns_snapshot"
	} else {
		result.DNSPath = "proxy_remote_resolution"
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if runContext != nil {
		if runContext.Err() != nil {
			cancel()
		}
		stop := context.AfterFunc(runContext, cancel)
		defer stop()
	}
	conn, dialErr := one.dialDiagnosticSnapshot(ctx, snapshot, outbound, target)
	if dialErr != nil {
		result.Stage = DiagnosticStage(dialErr)
		if result.Stage == "" {
			result.Stage = info.Stage
		}
		result.Message = diagnosticMessage(dialErr, snapshot.cfg)
		if errors.Is(dialErr, context.Canceled) {
			result.Status = "canceled"
		} else if result.Stage == "virtual_destination" {
			result.Status = "unsupported"
		}
		return result, nil
	}
	defer conn.Close()
	if remote := conn.RemoteAddr(); remote != nil {
		result.RemoteAddress = remote.String()
	}
	if withTLS {
		result.Stage = "target_tls"
		client := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if tlsErr := client.HandshakeContext(ctx); tlsErr != nil {
			result.Message = diagnosticMessage(tlsErr, snapshot.cfg)
			if errors.Is(tlsErr, context.Canceled) {
				result.Status = "canceled"
			}
			return result, nil
		}
		result.Status = "reachable"
		result.Message = "TCP and verified target TLS succeeded; no application request was sent"
		return result, nil
	}
	if !info.TargetAcknowledged {
		result.Status = "unknown"
		result.Message = "Encrypted proxy transport opened; this protocol provides no target connection acknowledgement"
		return result, nil
	}
	result.Status = "reachable"
	result.Message = "TCP connection setup succeeded; application behavior was not tested"
	return result, nil
}

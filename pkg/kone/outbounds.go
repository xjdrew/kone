package kone

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/xjdrew/kone/pkg/proxy"
)

type configuredOutbound struct {
	kind        OutboundType
	proxy       *proxy.Proxy
	udpFallback string
}

var ErrUDPUnsupported = errors.New("outbound does not support UDP")
var ErrRejected = errors.New("connection rejected by routing policy")

type Outbounds struct {
	entries map[string]configuredOutbound
	dial    func(context.Context, string, string) (net.Conn, error)
}

func (p *Outbounds) Dial(name, addr string) (net.Conn, error) {
	return p.DialContext(context.Background(), name, addr)
}

func (p *Outbounds) DialContext(ctx context.Context, name, addr string) (net.Conn, error) {
	outbound, ok := p.entries[name]
	if !ok {
		return nil, fmt.Errorf("unknown outbound %q", name)
	}
	switch outbound.kind {
	case OutboundReject:
		return nil, ErrRejected
	case OutboundDirect:
		return p.dial(ctx, "tcp", addr)
	case OutboundProxy:
		slog.Debug("Dialing proxy", "destination", addr, "outbound", name)
		return outbound.proxy.DialContextVia(ctx, "tcp", addr, p.dial)
	}
	return nil, fmt.Errorf("invalid outbound type for %q", name)
}

// SupportsUDP describes the actual transport implementation. Native SOCKS5/SS
// associations are distinct from explicit direct fallback on TCP-only proxies.
func (p *Outbounds) SupportsUDP(name string) bool {
	entry, ok := p.entries[name]
	return ok && (entry.kind == OutboundDirect || entry.kind == OutboundProxy && entry.proxy.SupportsUDP())
}

// UDPOutbound resolves policy before DNS or dialing. Fallbacks are explicitly
// configured terminal targets, and can never turn a reject rule into a dial.
func (p *Outbounds) UDPOutbound(name string) (string, error) {
	entry, ok := p.entries[name]
	if !ok {
		return "", fmt.Errorf("unknown outbound %q", name)
	}
	if entry.kind == OutboundReject {
		return "", fmt.Errorf("outbound %q: %w", name, ErrRejected)
	}
	if p.SupportsUDP(name) {
		return name, nil
	}
	switch entry.udpFallback {
	case BuiltinDirect:
		return BuiltinDirect, nil
	case BuiltinReject:
		return "", fmt.Errorf("outbound %q UDP fallback reject: %w", name, ErrRejected)
	default:
		return "", fmt.Errorf("outbound %q: %w; configure udp-fallback explicitly to allow direct UDP", name, ErrUDPUnsupported)
	}
}

func (p *Outbounds) DialUDPContext(ctx context.Context, name, addr string) (net.Conn, error) {
	target, err := p.UDPOutbound(name)
	if err != nil {
		return nil, err
	}
	if target == BuiltinDirect {
		return p.dial(ctx, "udp4", addr)
	}
	// A failed association is a real proxy failure, never permission to
	// silently switch to direct or to execute an unrelated fallback policy.
	return p.entries[target].proxy.DialUDPContextVia(ctx, addr, p.dial)
}

func NewOutbounds(config []OutboundConfig) (*Outbounds, error) {
	if _, err := validateOutbounds(config); err != nil {
		return nil, err
	}
	p := &Outbounds{entries: make(map[string]configuredOutbound, len(config)+2), dial: proxy.Direct.DialContext}
	for name, kind := range builtinOutbounds() {
		p.entries[name] = configuredOutbound{kind: kind}
	}
	for _, o := range config {
		dialer, _ := proxy.FromUrl(o.URL) // validated above; never log credentials
		slog.Debug("Proxy configured", "outbound", o.Name, "scheme", dialer.Url.Scheme, "endpoint", dialer.Url.Host)
		p.entries[o.Name] = configuredOutbound{kind: OutboundProxy, proxy: dialer, udpFallback: o.UDPFallback}
	}
	return p, nil
}

func (p *Outbounds) bypassEndpoints(rule *Rule) {
	for _, entry := range p.entries {
		if entry.kind == OutboundProxy {
			rule.DirectDomain(entry.proxy.Url.Hostname())
		}
	}
}

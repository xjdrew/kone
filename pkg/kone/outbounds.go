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
	kind  OutboundType
	proxy *proxy.Proxy
}

type Outbounds struct {
	entries map[string]configuredOutbound
	dial    func(context.Context, string, string) (net.Conn, error)
}

func (p *Outbounds) Dial(name, addr string) (net.Conn, error) {
	return p.DialContext(context.Background(), name, addr)
}

func (p *Outbounds) DialContext(ctx context.Context, name, addr string) (net.Conn, error) {
	outbound, ok := p.entries[name]
	if name == "" {
		outbound, ok = configuredOutbound{kind: OutboundDirect}, true
	}
	if !ok {
		return nil, fmt.Errorf("unknown outbound %q", name)
	}
	switch outbound.kind {
	case OutboundReject:
		return nil, errors.New("connection rejected by routing policy")
	case OutboundDirect:
		return p.dial(ctx, "tcp", addr)
	case OutboundProxy:
		slog.Debug("Dialing proxy", "destination", addr, "outbound", name)
		return outbound.proxy.DialContextVia(ctx, "tcp", addr, p.dial)
	}
	return nil, fmt.Errorf("invalid outbound type for %q", name)
}

func NewOutbounds(config []OutboundConfig) (*Outbounds, error) {
	if _, err := validateOutbounds(config); err != nil {
		return nil, err
	}
	p := &Outbounds{entries: make(map[string]configuredOutbound, len(config)), dial: proxy.Direct.DialContext}
	for _, o := range config {
		entry := configuredOutbound{kind: o.Type}
		if o.Type == OutboundProxy {
			entry.proxy, _ = proxy.FromUrl(o.URL) // validated above; never log credentials
			slog.Debug("Proxy configured", "outbound", o.Name, "scheme", entry.proxy.Url.Scheme, "endpoint", entry.proxy.Url.Host)
		}
		p.entries[o.Name] = entry
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

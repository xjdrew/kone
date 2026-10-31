package kone

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/xjdrew/kone/pkg/proxy"
)

type Proxies struct{ proxies map[string]*proxy.Proxy }

func (p *Proxies) Dial(name, addr string) (net.Conn, error) {
	return p.DialContext(context.Background(), name, addr)
}

func (p *Proxies) DialContext(ctx context.Context, name, addr string) (net.Conn, error) {
	if name == "REJECT" {
		return nil, errors.New("connection rejected by routing policy")
	}
	if name == "DIRECT" {
		return proxy.Direct.DialContext(ctx, "tcp", addr)
	}
	slog.Debug("Dialing proxy", "destination", addr, "proxy", name)
	if dialer := p.proxies[name]; dialer != nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}
	return nil, fmt.Errorf("unknown proxy %q", name)
}

func NewProxies(config map[string]string) (*Proxies, error) {
	p := &Proxies{proxies: make(map[string]*proxy.Proxy, len(config))}
	for name, raw := range config {
		dialer, err := proxy.FromUrl(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q", name)
		}
		p.proxies[name] = dialer
		// Never log URLs: they may contain authentication credentials.
		slog.Debug("Proxy configured", "proxy", name, "scheme", dialer.Url.Scheme, "endpoint", dialer.Url.Host)
	}
	return p, nil
}

func (p *Proxies) bypassEndpoints(rule *Rule) {
	for _, dialer := range p.proxies {
		rule.DirectDomain(dialer.Url.Hostname())
	}
}

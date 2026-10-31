//
//   date  : 2016-05-13
//   author: xjdrew
//

package proxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// A Dialer is a means to establish a connection.
type Dialer interface {
	// Dial connects to the given address via the proxy.
	Dial(network, addr string) (c net.Conn, err error)
}

// proxySchemes is a map from URL schemes to a function that creates a Dialer
// from a URL with such a scheme.
var proxySchemes = make(map[string]func(*url.URL, Dialer) (Dialer, error))

// RegisterDialerType takes a URL scheme and a function to generate Dialers from
// a URL with that scheme and a forwarding Dialer. Registered schemes are used
// by FromURL.
func registerDialerType(scheme string, f func(*url.URL, Dialer) (Dialer, error)) {
	proxySchemes[scheme] = f
}

func getDialerByURL(u *url.URL, forward Dialer) (Dialer, error) {
	if f, ok := proxySchemes[u.Scheme]; ok {
		return f(u, forward)
	}
	return nil, errors.New("proxy: unknown scheme: " + u.Scheme)
}

type Proxy struct {
	Url    *url.URL
	dialer Dialer
}

func (p *Proxy) Dial(network, addr string) (net.Conn, error) {
	return p.DialContext(context.Background(), network, addr)
}

type cancelForward struct {
	ctx     context.Context
	dial    func(context.Context, string, string) (net.Conn, error)
	stop    func() bool
	stopped chan struct{}
}

func (f *cancelForward) Dial(network, addr string) (net.Conn, error) {
	conn, err := f.dial(f.ctx, network, addr)
	if err != nil {
		return nil, atStage(StageConnect, err)
	}
	f.stopped = make(chan struct{})
	f.stop = context.AfterFunc(f.ctx, func() { conn.Close(); close(f.stopped) })
	return conn, nil
}

// DialContext cancels both dialing and the protocol handshake. The cancellation
// hook is detached before returning, so it never closes an established tunnel.
func (p *Proxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.DialContextVia(ctx, network, addr, Direct.DialContext)
}

// DialContextVia routes the transport through the engine's physical-interface
// dialer without changing global dialers or the proxy protocol handshake.
func (p *Proxy) DialContextVia(ctx context.Context, network, addr string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	forward := &cancelForward{ctx: ctx, dial: dial}
	dialer, err := getDialerByURL(p.Url, forward)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.Dial(network, addr)
	if forward.stop != nil && !forward.stop() {
		<-forward.stopped
	}
	if ctx.Err() != nil {
		if conn != nil {
			conn.Close()
		}
		stage := ErrorStage(err)
		if stage == "" {
			stage = StageHandshake
		}
		return nil, atStage(stage, ctx.Err())
	}
	return conn, atStage(StageHandshake, err)
}

func FromUrl(rawurl string) (*Proxy, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, errors.New("proxy: invalid URL")
	}
	if u.Scheme == "ss" {
		if err := normalizeShadowsocksURL(u); err != nil {
			return nil, err
		}
	}
	if u.Opaque != "" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(u.Host, " \t\r\n") {
		return nil, errors.New("proxy: expected scheme://host:port without path, query or fragment")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("proxy: explicit port between 1 and 65535 required")
	}

	dailer, err := getDialerByURL(u, Direct)
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{
		Url:    u,
		dialer: dailer,
	}

	return proxy, nil
}

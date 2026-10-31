//
//   date  : 2016-05-13
//   author: xjdrew
//

package proxy

import (
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
	return p.dialer.Dial(network, addr)
}

func FromUrl(rawurl string) (*Proxy, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, errors.New("proxy: invalid URL")
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

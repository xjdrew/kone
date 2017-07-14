//
//   date  : 2016-05-13
//   author: xjdrew
//

package proxy

import (
	"net"
	"net/url"

	"golang.org/x/net/proxy"
)

type Conn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

type Proxy struct {
	Url *url.URL

	dialer proxy.Dialer
}

func (p *Proxy) Dial(network, addr string) (Conn, error) {
	conn, err := p.dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	return conn.(Conn), nil
}

func FromUrl(rawurl string) (*Proxy, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	dailer, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{
		Url:    u,
		dialer: dailer,
	}

	return proxy, nil
}

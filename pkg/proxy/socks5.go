package proxy

import (
	"net"
	"net/url"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// Bound the entire SOCKS handshake, not only the connection to the proxy.
type handshakeForward struct{ Dialer }

func (d handshakeForward) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type socks5 struct{ dialer xproxy.Dialer }

func (s socks5) Dial(network, addr string) (net.Conn, error) {
	conn, err := s.dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func init() {
	registerDialerType("socks5", func(u *url.URL, forward Dialer) (Dialer, error) {
		var auth *xproxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: password}
		}
		dialer, err := xproxy.SOCKS5("tcp", u.Host, auth, handshakeForward{forward})
		if err != nil {
			return nil, err
		}
		return socks5{dialer: dialer}, nil
	})
}

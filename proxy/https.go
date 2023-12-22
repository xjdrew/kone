package proxy

import (
	"crypto/tls"
	"net"
	"net/url"
	"strings"
)

type tlsDialer struct {
	forward Dialer
}

func hostname(addr string) string {
	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		return addr
	}
	return addr[:colonPos]
}

func (h *tlsDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := h.forward.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: hostname(addr),
	})
	return tlsConn, nil
}

func init() {
	registerDialerType("https", func(url *url.URL, forward Dialer) (Dialer, error) {
		dialer := &tlsDialer{
			forward: forward,
		}
		return &http11{
			addr:    url.Host,
			user:    url.User,
			forward: dialer,
		}, nil
	})
}

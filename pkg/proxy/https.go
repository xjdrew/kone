package proxy

import (
	"crypto/tls"
	"net"
	"net/url"
	"time"
)

type tlsDialer struct {
	forward Dialer
}

func hostname(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (h *tlsDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := h.forward.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: hostname(addr),
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return nil, atStage(StageTLS, err)
	}
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, atStage(StageTLS, err)
	}
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

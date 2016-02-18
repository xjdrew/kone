package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"golang.org/x/net/proxy"
)

type httpTunnel struct {
	addr    string
	user    *url.Userinfo
	forward proxy.Dialer
}

func HttpTunnel(url *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	return &httpTunnel{
		addr:    url.Host,
		user:    url.User,
		forward: forward,
	}, nil
}

func (h *httpTunnel) Dial(network, addr string) (net.Conn, error) {
	conn, err := h.forward.Dial(network, h.addr)
	if err != nil {
		return nil, err
	}

	clientConn := httputil.NewClientConn(conn, nil)
	req := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			User: h.user,
			Host: addr,
		},
	}

	resp, err := clientConn.Do(req)
	if err != nil && err != httputil.ErrPersistEOF {
		clientConn.Close()
		return nil, err
	}

	if resp.StatusCode != 200 {
		clientConn.Close()
		return nil, errors.New(resp.Status)
	}

	conn, _ = clientConn.Hijack()
	return conn, nil
}

func init() {
	proxy.RegisterDialerType("http", func(url *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
		return &httpTunnel{
			addr:    url.Host,
			user:    url.User,
			forward: forward,
		}, nil
	})
}

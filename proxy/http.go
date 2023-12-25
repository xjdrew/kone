//
//   date  : 2016-02-18
//   author: xjdrew
//
package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
)

type http11 struct {
	addr    string
	user    *url.Userinfo
	forward Dialer
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (h *http11) Dial(network, addr string) (net.Conn, error) {
	conn, err := h.forward.Dial(network, h.addr)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Host: addr,
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}

	req.Header.Set("Proxy-Connection", "keep-alive")

	// req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	if h.user != nil {
		if password, ok := h.user.Password(); ok {
			req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(h.user.Username(), password))
		}
	}

	if err = req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	var resp *http.Response
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	//defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, errors.New(resp.Status)
	}

	return conn, nil
}

func init() {
	registerDialerType("http", func(url *url.URL, forward Dialer) (Dialer, error) {
		return &http11{
			addr:    url.Host,
			user:    url.User,
			forward: forward,
		}, nil
	})
}

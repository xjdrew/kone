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
	"sync"
)

type http11 struct {
	addr    string
	user    *url.Userinfo
	forward Dialer
}

type httpConn struct {
	net.Conn
	reader *bufio.Reader
	req    *http.Request

	sync.Mutex
	connErr  error
	connResp bool
}

func (c *httpConn) readConnectResponse() error {
	c.Lock()
	defer c.Unlock()

	// double check
	if c.connResp {
		return c.connErr
	}

	// set connResp
	c.connResp = true

	resp, err := http.ReadResponse(c.reader, c.req)

	// release req
	c.req = nil

	if err != nil {
		c.connErr = err
		return c.connErr
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.connErr = errors.New(resp.Status)
		return c.connErr
	}

	return c.connErr
}

func (c *httpConn) Read(p []byte) (int, error) {
	if !c.connResp {
		err := c.readConnectResponse()
		if err != nil {
			return 0, err
		}
	}
	return c.reader.Read(p)
}

func newHttpConn(conn net.Conn, req *http.Request) *httpConn {
	return &httpConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
		req:    req,
	}
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

	if h.user != nil {
		if password, ok := h.user.Password(); ok {
			req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(h.user.Username(), password))
		}
	}

	if err = req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return newHttpConn(conn, req), nil
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

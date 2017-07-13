//
//   date  : 2016-02-18
//   author: xjdrew
//
package proxy

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/proxy"
)

type httpTunnel struct {
	addr    string
	user    *url.Userinfo
	forward proxy.Dialer
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

	req := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			User: h.user,
			Host: addr,
		},
	}

	if err = req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return newHttpConn(conn, req), nil
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

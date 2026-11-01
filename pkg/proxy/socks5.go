package proxy

import (
	"net"
	"net/url"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// Bound the entire SOCKS handshake, not only the connection to the proxy.
type handshakeForward struct {
	Dialer
	state *socksAuthState
}

type socksAuthState struct {
	phase    int
	read     int
	reply    [2]byte
	rejected bool
}
type socksAuthConn struct {
	net.Conn
	state *socksAuthState
}

func (c *socksAuthConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *socksAuthConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	state := c.state
	for _, value := range data[:n] {
		if state.phase >= 2 {
			break
		}
		state.reply[state.read] = value
		state.read++
		if state.read < 2 {
			continue
		}
		state.read = 0
		if state.phase == 0 {
			if state.reply[0] != 5 {
				state.phase = 2
				continue
			}
			switch state.reply[1] {
			case 0:
				state.phase = 2
			case 2:
				state.phase = 1
			default:
				state.rejected = true
				state.phase = 2
			}
		} else {
			state.rejected = state.reply[0] != 1 || state.reply[1] != 0
			state.phase = 2
		}
	}
	return n, err
}

func (d handshakeForward) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	return &socksAuthConn{Conn: conn, state: d.state}, nil
}

type socks5 struct {
	dialer xproxy.Dialer
	state  *socksAuthState
}

func (s socks5) Dial(network, addr string) (net.Conn, error) {
	conn, err := s.dialer.Dial(network, addr)
	if err != nil {
		if s.state.rejected || s.state.phase == 1 {
			return nil, atStage(StageAuth, err)
		}
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
		state := new(socksAuthState)
		dialer, err := xproxy.SOCKS5("tcp", u.Host, auth, handshakeForward{Dialer: forward, state: state})
		if err != nil {
			return nil, err
		}
		return socks5{dialer: dialer, state: state}, nil
	})
}

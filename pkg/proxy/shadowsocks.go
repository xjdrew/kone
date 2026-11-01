package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/sagernet/sing-shadowsocks2/cipher"
	"github.com/sagernet/sing-shadowsocks2/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

// Accept SIP002 AEAD userinfo, including its optional trailing slash and tag.
// Plugins and AEAD-2022 are deliberately outside the supported protocol set.
func normalizeShadowsocksURL(u *url.URL) error {
	if u.User == nil || u.RawQuery != "" || u.Path != "" && u.Path != "/" {
		return errors.New("proxy: ss URL requires method/password and does not support plugins")
	}
	method, password := u.User.Username(), ""
	var present bool
	password, present = u.User.Password()
	if !present {
		decoded := false
		for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			data, err := encoding.DecodeString(method)
			if err != nil {
				continue
			}
			if name, secret, found := strings.Cut(string(data), ":"); found {
				method, password, decoded = name, secret, true
				break
			}
		}
		if !decoded {
			return errors.New("proxy: invalid ss method/password encoding")
		}
	}
	switch method {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
	default:
		return errors.New("proxy: supported ss methods are aes-128-gcm, aes-256-gcm and chacha20-ietf-poly1305")
	}
	if password == "" || len(password) > 1024 || strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("proxy: ss password must contain 1..1024 bytes without control characters")
	}
	u.User = url.UserPassword(method, password)
	u.Path, u.Fragment, u.RawFragment = "", "", ""
	return nil
}

func shadowsocksMethod(u *url.URL) (C.Method, error) {
	password, _ := u.User.Password()
	method, err := shadowaead.NewMethod(context.Background(), u.User.Username(), C.MethodOptions{Password: password})
	if err != nil {
		return nil, errors.New("invalid Shadowsocks settings")
	}
	return method, nil
}

type shadowsocksDialer struct {
	forward Dialer
	server  string
	method  C.Method
}

func (d *shadowsocksDialer) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("Shadowsocks stream dial requires TCP")
	}
	target, err := parseSOCKSTarget(address)
	if err != nil {
		return nil, err
	}
	conn, err := d.forward.Dial(network, d.server)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	stream, err := d.method.DialConn(conn, M.ParseSocksaddr(net.JoinHostPort(target.host, strconv.Itoa(int(target.port)))))
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func init() {
	registerDialerType("ss", func(u *url.URL, forward Dialer) (Dialer, error) {
		method, err := shadowsocksMethod(u)
		if err != nil {
			return nil, err
		}
		return &shadowsocksDialer{forward: forward, server: u.Host, method: method}, nil
	})
}

func (p *Proxy) dialShadowsocksUDP(ctx context.Context, address string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	target, err := parseSOCKSTarget(address)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	method, err := shadowsocksMethod(p.Url)
	if err != nil {
		return nil, err
	}
	outer, err := dial(ctx, "udp", p.Url.Host)
	if err != nil {
		return nil, err
	}
	packet := method.DialPacketConn(outer)
	conn := &shadowsocksUDPConn{packet: packet, target: target, readBuffer: make([]byte, 65535)}
	conn.cancelMu.Lock()
	conn.stopCancel = context.AfterFunc(ctx, func() { conn.Close() })
	conn.cancelMu.Unlock()
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// The encrypted UDP transport stays connected to the configured server. Its
// authenticated response address must also match this business association.
type shadowsocksUDPConn struct {
	packet     net.PacketConn
	target     socksAddress
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readBuffer []byte
	closeOnce  sync.Once
	closeErr   error
	cancelMu   sync.Mutex
	stopCancel func() bool
}

func (c *shadowsocksUDPConn) Read(payload []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, source, err := c.packet.ReadFrom(c.readBuffer)
	if err != nil {
		return 0, err
	}
	actual, err := parseSOCKSTarget(source.String())
	if err != nil || actual.port != c.target.port {
		return 0, ErrSOCKSUDPSource
	}
	if expected, err := netip.ParseAddr(c.target.host); err == nil {
		ip, err := netip.ParseAddr(actual.host)
		if err != nil || ip.Unmap() != expected.Unmap() {
			return 0, ErrSOCKSUDPSource
		}
	} else if _, err := netip.ParseAddr(actual.host); err != nil && !strings.EqualFold(actual.host, c.target.host) {
		return 0, ErrSOCKSUDPSource
	}
	count := copy(payload, c.readBuffer[:n])
	if count < n {
		return count, io.ErrShortBuffer
	}
	return count, nil
}

func (c *shadowsocksUDPConn) Write(payload []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Leave space for the largest supported salt, authentication tag and
	// destination; reject locally instead of allocating an oversized datagram.
	if len(payload) > 65507-32-16-1-1-253-2 {
		return 0, errors.New("Shadowsocks UDP payload exceeds datagram limit")
	}
	return c.packet.WriteTo(payload, M.ParseSocksaddr(net.JoinHostPort(c.target.host, strconv.Itoa(int(c.target.port)))))
}

func (c *shadowsocksUDPConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancelMu.Lock()
		stop := c.stopCancel
		c.cancelMu.Unlock()
		if stop != nil {
			stop()
		}
		c.closeErr = c.packet.Close()
	})
	return c.closeErr
}
func (c *shadowsocksUDPConn) LocalAddr() net.Addr { return c.packet.LocalAddr() }
func (c *shadowsocksUDPConn) RemoteAddr() net.Addr {
	return socksUDPRemoteAddr(net.JoinHostPort(c.target.host, strconv.Itoa(int(c.target.port))))
}
func (c *shadowsocksUDPConn) SetDeadline(t time.Time) error      { return c.packet.SetDeadline(t) }
func (c *shadowsocksUDPConn) SetReadDeadline(t time.Time) error  { return c.packet.SetReadDeadline(t) }
func (c *shadowsocksUDPConn) SetWriteDeadline(t time.Time) error { return c.packet.SetWriteDeadline(t) }

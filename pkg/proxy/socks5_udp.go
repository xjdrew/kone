package proxy

// SOCKS UDP framing and association follow RFC 1928 sections 6/7; optional
// username/password negotiation follows RFC 1929. Fragment reassembly is not
// implemented: nonzero FRAG datagrams are rejected rather than misdelivered.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrSOCKSUDPFragment = errors.New("fragmented SOCKS5 UDP datagrams are unsupported")
var ErrSOCKSUDPSource = errors.New("unexpected SOCKS5 UDP response source")

type socksAddress struct {
	host string
	port uint16
}

func parseSOCKSTarget(addr string) (socksAddress, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return socksAddress{}, errors.New("SOCKS target requires host and port")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 || !validSOCKSHost(host) {
		return socksAddress{}, errors.New("invalid SOCKS target address")
	}
	return socksAddress{host: strings.TrimSuffix(strings.ToLower(host), "."), port: uint16(value)}, nil
}

func validSOCKSHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t /\\%") {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == ""
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if ch != '-' && ch != '_' && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
				return false
			}
		}
	}
	return true
}

func appendSOCKSAddress(buffer []byte, address socksAddress) ([]byte, error) {
	if ip, err := netip.ParseAddr(address.host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			raw := ip.As4()
			buffer = append(buffer, 1)
			buffer = append(buffer, raw[:]...)
		} else {
			raw := ip.As16()
			buffer = append(buffer, 4)
			buffer = append(buffer, raw[:]...)
		}
	} else {
		if !validSOCKSHost(address.host) || len(address.host) > 255 {
			return nil, errors.New("invalid SOCKS domain")
		}
		buffer = append(buffer, 3, byte(len(address.host)))
		buffer = append(buffer, address.host...)
	}
	return append(buffer, byte(address.port>>8), byte(address.port)), nil
}

func readSOCKSAddress(reader io.Reader, kind byte) (socksAddress, error) {
	var raw []byte
	switch kind {
	case 1:
		raw = make([]byte, 4)
	case 4:
		raw = make([]byte, 16)
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return socksAddress{}, err
		}
		if size[0] == 0 {
			return socksAddress{}, errors.New("empty SOCKS domain")
		}
		raw = make([]byte, int(size[0]))
	default:
		return socksAddress{}, errors.New("unsupported SOCKS address type")
	}
	if _, err := io.ReadFull(reader, raw); err != nil {
		return socksAddress{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return socksAddress{}, err
	}
	host := string(raw)
	if kind != 3 {
		address, _ := netip.AddrFromSlice(raw)
		host = address.Unmap().String()
	}
	if !validSOCKSHost(host) {
		return socksAddress{}, errors.New("invalid SOCKS relay/source address")
	}
	return socksAddress{host: strings.TrimSuffix(strings.ToLower(host), "."), port: binary.BigEndian.Uint16(port[:])}, nil
}

func writeSOCKSMessage(conn net.Conn, message []byte) error {
	n, err := conn.Write(message)
	if err == nil && n != len(message) {
		err = io.ErrShortWrite
	}
	return err
}

func (p *Proxy) SupportsUDP() bool {
	return p != nil && p.Url != nil && (p.Url.Scheme == "socks5" || p.Url.Scheme == "ss")
}

func (p *Proxy) DialUDPContext(ctx context.Context, addr string) (net.Conn, error) {
	return p.DialUDPContextVia(ctx, addr, Direct.DialContext)
}

func (p *Proxy) DialUDPContextVia(ctx context.Context, addr string, dial func(context.Context, string, string) (net.Conn, error)) (connection net.Conn, result error) {
	if !p.SupportsUDP() {
		return nil, errors.New("proxy does not support UDP")
	}
	if p.Url.Scheme == "ss" {
		return p.dialShadowsocksUDP(ctx, addr, dial)
	}
	target, err := parseSOCKSTarget(addr)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	control, err := dial(ctx, "tcp", p.Url.Host)
	if err != nil {
		return nil, err
	}
	var packet net.Conn
	success := false
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { control.Close(); close(closed) })
	detach := func() {
		if stop != nil {
			current := stop
			stop = nil
			if !current() {
				<-closed
			}
		}
	}
	defer func() {
		detach()
		if !success {
			control.Close()
			if packet != nil {
				packet.Close()
			}
		}
		if result != nil && ctx.Err() != nil {
			result = ctx.Err()
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err := control.SetDeadline(deadline); err != nil {
		return nil, err
	}
	greeting := []byte{5, 1, 0}
	if p.Url.User != nil {
		greeting = []byte{5, 2, 0, 2}
	}
	if err := writeSOCKSMessage(control, greeting); err != nil {
		return nil, err
	}
	var selected [2]byte
	if _, err := io.ReadFull(control, selected[:]); err != nil {
		return nil, err
	}
	if selected[0] != 5 {
		return nil, errors.New("invalid SOCKS authentication reply")
	}
	switch selected[1] {
	case 0:
	case 2:
		if p.Url.User == nil {
			return nil, errors.New("SOCKS proxy requires credentials")
		}
		username := p.Url.User.Username()
		password, _ := p.Url.User.Password()
		if len(username) == 0 || len(username) > 255 || len(password) == 0 || len(password) > 255 {
			return nil, errors.New("SOCKS username/password must contain 1..255 bytes")
		}
		auth := append([]byte{1, byte(len(username))}, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if err := writeSOCKSMessage(control, auth); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(control, selected[:]); err != nil {
			return nil, err
		}
		if selected[0] != 1 || selected[1] != 0 {
			return nil, errors.New("SOCKS authentication rejected")
		}
	default:
		return nil, errors.New("SOCKS authentication method unsupported or rejected")
	}
	// At association time the UDP socket/port is not yet known, so RFC 1928
	// requires an all-zero address and port in the UDP ASSOCIATE request.
	if err := writeSOCKSMessage(control, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[2] != 0 {
		return nil, errors.New("invalid SOCKS UDP association reply")
	}
	if reply[1] != 0 {
		return nil, fmt.Errorf("SOCKS UDP association rejected (code %d)", reply[1])
	}
	relay, err := readSOCKSAddress(control, reply[3])
	if err != nil || relay.port == 0 {
		return nil, errors.New("invalid SOCKS UDP relay address")
	}
	peerHost, _, err := net.SplitHostPort(control.RemoteAddr().String())
	if err != nil {
		return nil, errors.New("SOCKS control peer has no IP address")
	}
	peerIP, err := netip.ParseAddr(peerHost)
	if err != nil {
		return nil, errors.New("SOCKS control peer must have a literal IP address")
	}
	if relayIP, err := netip.ParseAddr(relay.host); err == nil {
		relayIP = relayIP.Unmap()
		if relayIP.IsUnspecified() {
			relay.host = peerIP.Unmap().String()
		} else if relayIP.IsMulticast() {
			return nil, errors.New("SOCKS UDP relay cannot be multicast")
		}
		if relayIP.IsLoopback() && !peerIP.Unmap().IsLoopback() {
			return nil, errors.New("remote SOCKS proxy cannot redirect UDP to loopback")
		}
	} else {
		// Never resolve an arbitrary hostname supplied by a proxy. A reply
		// naming this configured proxy can safely reuse its connected peer.
		if !strings.EqualFold(relay.host, strings.TrimSuffix(p.Url.Hostname(), ".")) {
			return nil, errors.New("SOCKS UDP relay hostname must match configured proxy")
		}
		relay.host = peerIP.Unmap().String()
	}
	packet, err = dial(ctx, "udp", net.JoinHostPort(relay.host, strconv.Itoa(int(relay.port))))
	if err != nil {
		return nil, err
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	detach()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	association := &socksUDPConn{control: control, packet: packet, target: target, readBuffer: make([]byte, 65535), monitorDone: make(chan struct{})}
	association.cancelMu.Lock()
	association.stopCancel = context.AfterFunc(ctx, func() { association.Close() })
	association.cancelMu.Unlock()
	go func() {
		defer close(association.monitorDone)
		var extra [1]byte
		control.Read(extra[:])
		association.Close()
	}()
	success = true
	if err := ctx.Err(); err != nil {
		association.Close()
		return nil, err
	}
	return association, nil
}

type socksUDPConn struct {
	control, packet net.Conn
	target          socksAddress
	readMu          sync.Mutex
	readBuffer      []byte
	writeMu         sync.Mutex
	closeOnce       sync.Once
	closeErr        error
	cancelMu        sync.Mutex
	stopCancel      func() bool
	monitorDone     chan struct{}
}

func (c *socksUDPConn) Read(payload []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.packet.Read(c.readBuffer)
	if err != nil {
		return 0, err
	}
	if n < 4 || c.readBuffer[0] != 0 || c.readBuffer[1] != 0 {
		return 0, errors.New("invalid SOCKS UDP header")
	}
	if c.readBuffer[2] != 0 {
		return 0, ErrSOCKSUDPFragment
	}
	reader := bytes.NewReader(c.readBuffer[4:n])
	source, err := readSOCKSAddress(reader, c.readBuffer[3])
	if err != nil {
		return 0, err
	}
	if source.port != c.target.port {
		return 0, ErrSOCKSUDPSource
	}
	if expected, err := netip.ParseAddr(c.target.host); err == nil {
		actual, err := netip.ParseAddr(source.host)
		if err != nil || actual.Unmap() != expected.Unmap() {
			return 0, ErrSOCKSUDPSource
		}
	} else if _, err := netip.ParseAddr(source.host); err != nil && !strings.EqualFold(source.host, c.target.host) {
		return 0, ErrSOCKSUDPSource
	}
	data := c.readBuffer[n-reader.Len() : n]
	count := copy(payload, data)
	if count < len(data) {
		return count, io.ErrShortBuffer
	}
	return count, nil
}

func (c *socksUDPConn) Write(payload []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	packet, err := appendSOCKSAddress([]byte{0, 0, 0}, c.target)
	if err != nil {
		return 0, err
	}
	if len(payload)+len(packet) > 65507 {
		return 0, errors.New("SOCKS UDP payload exceeds datagram limit")
	}
	packet = append(packet, payload...)
	n, err := c.packet.Write(packet)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(payload), nil
}

func (c *socksUDPConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancelMu.Lock()
		stop := c.stopCancel
		c.cancelMu.Unlock()
		if stop != nil {
			stop()
		}
		c.closeErr = errors.Join(c.packet.Close(), c.control.Close())
	})
	return c.closeErr
}

type socksUDPRemoteAddr string

func (a socksUDPRemoteAddr) Network() string { return "udp" }
func (a socksUDPRemoteAddr) String() string  { return string(a) }
func (c *socksUDPConn) LocalAddr() net.Addr  { return c.packet.LocalAddr() }
func (c *socksUDPConn) RemoteAddr() net.Addr {
	return socksUDPRemoteAddr(net.JoinHostPort(c.target.host, strconv.Itoa(int(c.target.port))))
}
func (c *socksUDPConn) SetDeadline(t time.Time) error      { return c.packet.SetDeadline(t) }
func (c *socksUDPConn) SetReadDeadline(t time.Time) error  { return c.packet.SetReadDeadline(t) }
func (c *socksUDPConn) SetWriteDeadline(t time.Time) error { return c.packet.SetWriteDeadline(t) }

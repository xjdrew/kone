package kone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// flowHandler adapts transparent connections to KONE policy. Addresses belong
// to the original LAN client, not to a desktop-only loopback listener.
type flowHandler struct {
	one     *One
	dialer  *net.Dialer
	mu      sync.Mutex
	closed  bool
	active  map[io.Closer]struct{}
	workers sync.WaitGroup
}

func (h *flowHandler) add(conn io.Closer, worker bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		closeFlow(conn)
		return false
	}
	if h.active == nil {
		h.active = make(map[io.Closer]struct{})
	}
	h.active[conn] = struct{}{}
	if worker {
		h.workers.Add(1)
	}
	return true
}
func closeFlow(conn io.Closer) {
	if d, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		d.SetDeadline(time.Now())
	}
	conn.Close()
}
func (h *flowHandler) remove(conn io.Closer) {
	conn.Close()
	h.mu.Lock()
	delete(h.active, conn)
	h.mu.Unlock()
}
func (h *flowHandler) close() {
	h.mu.Lock()
	h.closed = true
	for conn := range h.active {
		closeFlow(conn)
	}
	h.mu.Unlock()
}

func (*flowHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) singtun.FlowVerdict {
	return singtun.FlowVerdict{Action: singtun.ActionAccept}
}

func (h *flowHandler) destination(ctx context.Context, s *runtimeSnapshot, destination M.Socksaddr, udp bool) (string, string, error) {
	destination = destination.Unwrap()
	if !destination.Addr.Is4() {
		return "", "", errors.New("IPv6 interception is not configured")
	}
	ip := net.IP(destination.Addr.AsSlice())
	policy, host := s.rule.Proxy(ip), destination.Addr.String()
	if h.one.dnsTable.IsLocalIP(ip) {
		record := h.one.dnsTable.GetByIP(ip)
		if record == nil {
			return "", "", errors.New("unknown virtual address")
		}
		host = record.Hostname
		policy = s.rule.ProxyDNS(host, record.resolved)
		if policy != "REJECT" && (policy == "DIRECT" || udp) {
			if record.RealIP == nil {
				msg, err := h.one.dns.ResolveContext(ctx, host)
				if err != nil {
					return "", "", err
				}
				record.SetRealIP(msg)
				h.one.dnsTable.SetRealIP(host, msg)
			}
			if record.RealIP == nil {
				return "", "", errors.New("domain has no IPv4 address")
			}
			host = record.RealIP.String()
		}
	}
	if policy == "REJECT" {
		return "", policy, errors.New("connection rejected by routing policy")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(destination.Port))), policy, nil
}

func (h *flowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var result error
	defer func() {
		if result != nil && ctx.Err() == nil {
			slog.Debug("TCP flow ended", "source", source, "destination", destination, "error", result)
		}
		if onClose != nil {
			onClose(result)
		}
	}()
	if !h.add(conn, true) {
		result = net.ErrClosed
		return
	}
	defer h.workers.Done()
	defer h.remove(conn)
	s := h.one.policy.Load()
	addr, policy, err := h.destination(ctx, s, destination, false)
	if err != nil {
		result = err
		return
	}
	slog.Debug("TCP flow selected", "source", source, "destination", addr, "proxy", policy, "version", s.version)
	remote, err := s.proxies.DialContext(ctx, policy, addr)
	if err != nil {
		result = err
		return
	}
	if !h.add(remote, false) {
		result = net.ErrClosed
		return
	}
	defer h.remove(remote)
	upload, download := relayConnections(conn, remote)
	if h.one.manager != nil {
		h.one.manager.Record(ConnData{Src: source.AddrString(), Dst: addr, Proxy: policy, Upload: upload, Download: download})
	}
}

// Preserve the existing direct UDP behavior. The stack provides interception
// and sessions; SOCKS5 UDP ASSOCIATE remains an independent outbound feature.
func (h *flowHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var result error
	defer func() {
		if onClose != nil {
			onClose(result)
		}
	}()
	if !h.add(conn, true) {
		result = net.ErrClosed
		return
	}
	defer h.workers.Done()
	defer h.remove(conn)
	s := h.one.policy.Load()
	addr, _, err := h.destination(ctx, s, destination, true)
	if err != nil {
		result = err
		return
	}
	remote, err := h.dialer.DialContext(ctx, "udp4", addr)
	if err != nil {
		result = err
		return
	}
	if !h.add(remote, false) {
		result = net.ErrClosed
		return
	}
	defer h.remove(remote)
	stop := context.AfterFunc(ctx, func() { closeFlow(conn); closeFlow(remote) })
	defer stop()
	responses := make(chan error, 1)
	go func() {
		data := make([]byte, 65535)
		for {
			remote.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := remote.Read(data)
			if err != nil {
				responses <- err
				closeFlow(conn)
				return
			}
			if err = conn.WritePacket(buf.As(append([]byte(nil), data[:n]...)), destination); err != nil {
				responses <- err
				closeFlow(conn)
				return
			}
		}
	}()
	for {
		packet := buf.NewSize(65535)
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_, err := conn.ReadPacket(packet)
		if err == nil {
			_, err = remote.Write(packet.Bytes())
		}
		packet.Release()
		if err != nil {
			result = err
			break
		}
	}
	closeFlow(remote)
	<-responses
}

func (h *flowHandler) NewDNSPacket(payload []byte, source, _ M.Socksaddr, writer N.PacketWriter) {
	// Normal DNS enters the engine's owned listener. This also handles a future
	// library DNS-hijack callback without bypassing KONE's Fake-IP policy.
	request := new(dns.Msg)
	if err := request.Unpack(payload); err != nil || len(request.Question) != 1 {
		return
	}
	ctx := h.one.dns.ctx
	s := h.one.policy.Load()
	var reply *dns.Msg
	var err error
	if request.Question[0].Qtype == dns.TypeA {
		reply, err = h.one.dns.query(ctx, s, request)
	} else {
		reply, err = h.one.dns.resolve(ctx, request)
	}
	if err != nil {
		reply = new(dns.Msg)
		reply.SetRcode(request, dns.RcodeServerFailure)
	}
	data, err := reply.Pack()
	if err == nil {
		err = writer.WritePacket(buf.As(data), source)
	}
	if err != nil {
		slog.Debug("TUN DNS response failed", "error", fmt.Sprint(err))
	}
}

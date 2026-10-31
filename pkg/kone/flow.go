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
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	processinfo "github.com/xjdrew/kone/pkg/process"
)

// flowHandler adapts transparent connections to KONE policy. Addresses belong
// to the original LAN client, not to a desktop-only loopback listener.
type flowHandler struct {
	one       *One
	mu        sync.Mutex
	closed    bool
	active    map[io.Closer]struct{}
	workers   sync.WaitGroup
	observer  atomic.Pointer[TrafficObserver]
	processes *processinfo.Resolver
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
	processes := h.processes
	h.mu.Unlock()
	if processes != nil {
		processes.Close()
	}
}

func (h *flowHandler) attributeProcess(ctx context.Context, flow *ObservedFlow, protocol string, source, destination M.Socksaddr) {
	if ctx.Err() != nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	if h.processes == nil {
		h.processes = processinfo.New(processinfo.Options{})
	}
	resolver := h.processes
	h.mu.Unlock()
	if !resolver.LookupAsync(ctx, processinfo.Query{Protocol: protocol, Source: source.AddrPort(), Destination: destination.AddrPort(), ObservedAt: time.Now()}, flow.Process) {
		flow.Process(processinfo.Result{Status: "unknown", Reason: "process attribution queue is full or capture is stopping", Source: "bounded_process_queue", ObservedAt: time.Now()})
	}
}

func (*flowHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) singtun.FlowVerdict {
	return singtun.FlowVerdict{Action: singtun.ActionAccept}
}

type flowTarget struct {
	address         string
	outbound        string
	realDestination string
	decision        RoutingDecision
	release         func()
}

func (h *flowHandler) destination(ctx context.Context, s *runtimeSnapshot, destination M.Socksaddr, udp bool) (string, string, error) {
	target, err := h.resolveDestination(ctx, s, destination, udp, nil)
	if target.release != nil {
		target.release()
	}
	return target.address, target.outbound, err
}

func (h *flowHandler) resolveDestination(ctx context.Context, s *runtimeSnapshot, destination M.Socksaddr, udp bool, observation *ObservedFlow) (flowTarget, error) {
	target := flowTarget{}
	destination = destination.Unwrap()
	if !destination.Addr.Is4() && (!destination.Addr.Is6() || h.one.dnsTable6 == nil) {
		return target, errors.New("IPv6 interception is not configured")
	}
	protocol := "tcp"
	if udp {
		protocol = "udp"
	}
	ip := net.IP(destination.Addr.AsSlice())
	target.decision = s.rule.Decide(ip, protocol, destination.Port)
	host := destination.Addr.String()
	var record *DomainRecord
	table := h.one.tableForAddress(destination.Addr)
	if table.IsLocalIP(ip) {
		record = table.GetByIP(ip)
		if record == nil {
			return target, errors.New("unknown virtual address")
		}
		host = record.Hostname
		target.release = table.Pin(host)
		target.decision = s.rule.DecideDNS(host, record.resolved, protocol, destination.Port)
		if observation != nil {
			observation.UpdateTarget(host, destination.Addr.String(), net.JoinHostPort(host, strconv.Itoa(int(destination.Port))))
		}
	}
	selectOutbound := func(name string) (string, error) {
		if s.rule.OutboundType(name) == OutboundReject {
			return name, ErrRejected
		}
		if !udp {
			return name, nil
		}
		target, err := s.outbounds.UDPOutbound(name)
		if err != nil {
			return name, err
		}
		if target != name {
			slog.Debug("UDP fallback selected", "outbound", name, "udp_outbound", target, "reason", ErrUDPUnsupported.Error(), "version", s.version)
		}
		return target, nil
	}
	var err error
	target.outbound, err = selectOutbound(target.decision.Outbound)
	if observation != nil {
		observation.Decision(target.decision, target.outbound, "", false)
	}
	if err != nil {
		return target, err
	}
	if record != nil && s.rule.OutboundType(target.outbound) == OutboundDirect {
		if record.RealIP == nil {
			if observation != nil {
				observation.Stage("dns")
			}
			kind := uint16(dns.TypeA)
			if destination.Addr.Is6() {
				kind = dns.TypeAAAA
			}
			msg, err := h.one.dns.ResolveTypeContext(ctx, host, kind)
			if err != nil {
				return target, err
			}
			record.SetRealIP(msg)
			table.SetRealIP(host, msg)
			// A fresh resolution can reveal a CNAME/IP rule that was unknown
			// when the Fake-IP was allocated. Apply the same snapshot again.
			target.decision = s.rule.DecideDNS(record.Hostname, msg, protocol, destination.Port)
			target.outbound, err = selectOutbound(target.decision.Outbound)
			if observation != nil {
				observation.Decision(target.decision, target.outbound, "", false)
			}
			if err != nil {
				return target, err
			}
		}
		if s.rule.OutboundType(target.outbound) == OutboundDirect {
			if record.RealIP == nil {
				return target, errors.New("domain has no address matching the captured IP family")
			}
			host = record.RealIP.String()
		}
	}
	target.address = net.JoinHostPort(host, strconv.Itoa(int(destination.Port)))
	if address, err := netip.ParseAddr(host); err == nil && address.IsValid() {
		target.realDestination = target.address
	}
	return target, nil
}

func (h *flowHandler) stopping(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func (h *flowHandler) startObservation(s *runtimeSnapshot, protocol string, source, destination M.Socksaddr) *ObservedFlow {
	return h.one.TrafficObserver().Begin(FlowRecord{ConfigVersion: s.configurationVersion(), Inbound: "tun", Protocol: protocol, Source: source.String(), Destination: destination.String(), Target: destination.String(), DomainSource: "unknown", ProcessStatus: "unknown", ProcessReason: "process ownership not established"})
}

func (h *flowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var result error
	s := h.one.policy.Load()
	observation := h.startObservation(s, "tcp", source, destination)
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
		observation.Finish(result, true)
		return
	}
	defer h.workers.Done()
	h.attributeProcess(ctx, observation, "tcp", source, destination)
	defer func() { observation.Finish(result, h.stopping(ctx)) }()
	defer h.remove(conn)
	target, err := h.resolveDestination(ctx, s, destination, false, observation)
	if target.release != nil {
		defer target.release()
	}
	if err != nil {
		result = err
		return
	}
	addr, policy := target.address, target.outbound
	observation.Stage("dial")
	slog.Debug("TCP flow selected", "source", source, "destination", addr, "proxy", policy, "version", s.version)
	remote, err := s.outbounds.DialContext(ctx, policy, addr)
	if err != nil {
		result = err
		return
	}
	if !h.add(remote, false) {
		result = net.ErrClosed
		return
	}
	defer h.remove(remote)
	observation.Decision(target.decision, policy, target.realDestination, true)
	observation.Stage("transfer")
	upload, download := relayConnections(&observedConn{Conn: conn, flow: observation}, &observedConn{Conn: remote, flow: observation, upload: true})
	if h.one.manager != nil {
		h.one.manager.Record(ConnData{Src: source.AddrString(), Dst: addr, Proxy: policy, Upload: upload, Download: download})
	}
}

// Each UDP session retains one snapshot. Check policy/capability before any
// destination resolution or socket creation, and never silently bypass a proxy.
func (h *flowHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var result error
	s := h.one.policy.Load()
	observation := h.startObservation(s, "udp", source, destination)
	defer func() {
		if result != nil && ctx.Err() == nil {
			slog.Debug("UDP session ended", "source", source, "destination", destination, "error", result)
		}
		if onClose != nil {
			onClose(result)
		}
	}()
	if !h.add(conn, true) {
		result = net.ErrClosed
		observation.Finish(result, true)
		return
	}
	defer h.workers.Done()
	h.attributeProcess(ctx, observation, "udp", source, destination)
	defer func() { observation.Finish(result, h.stopping(ctx)) }()
	defer h.remove(conn)
	target, err := h.resolveDestination(ctx, s, destination, true, observation)
	if target.release != nil {
		defer target.release()
	}
	addr, policy := target.address, target.outbound
	if err != nil {
		slog.Warn("UDP outbound denied", "outbound", policy, "destination", destination, "reason", err.Error(), "version", s.version)
		result = err
		return
	}
	observation.Stage("dial")
	remote, err := s.outbounds.DialUDPContext(ctx, policy, addr)
	if err != nil {
		result = err
		return
	}
	if !h.add(remote, false) {
		result = net.ErrClosed
		return
	}
	defer h.remove(remote)
	observation.Decision(target.decision, policy, target.realDestination, true)
	observation.Stage("transfer")
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
			observation.AddDownload(uint64(n), 1)
		}
	}()
	for {
		packet := buf.NewSize(65535)
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_, err := conn.ReadPacket(packet)
		if err == nil {
			var n int
			n, err = remote.Write(packet.Bytes())
			if n > 0 || err == nil {
				observation.AddUpload(uint64(n), 1)
			}
		}
		packet.Release()
		if err != nil {
			result = err
			break
		}
	}
	closeFlow(remote)
	responseErr := <-responses
	if (result == nil || errors.Is(result, net.ErrClosed) || errors.Is(result, io.EOF)) && responseErr != nil && !errors.Is(responseErr, net.ErrClosed) {
		result = responseErr
	}
}

func (h *flowHandler) NewDNSPacket(payload []byte, source, _ M.Socksaddr, writer N.PacketWriter) {
	// Normal DNS enters the engine's owned listener. This also handles a future
	// library DNS-hijack callback without bypassing KONE's Fake-IP policy.
	request := new(dns.Msg)
	if err := request.Unpack(payload); err != nil || len(request.Question) != 1 {
		return
	}
	ctx := h.one.dns.ctx
	var reply *dns.Msg
	var err error
	reply, err = h.one.dns.HandleQuery(ctx, request, "udp", source.String())
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

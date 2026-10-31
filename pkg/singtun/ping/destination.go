package ping

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	// Although its theoretical maximum may be 64k, I don’t yet know of any practical use case for that. For memory-usage reasons, I’m just using a 2k buffer.
	maxICMPPacketSize = 2048
	requestsLimit     = 1024
)

type PacketWriter interface {
	WritePacket(packet []byte) error
}

type Destination struct {
	conn          *Conn
	ctx           context.Context
	logger        logger.ContextLogger
	destination   netip.Addr
	writer        PacketWriter
	timeout       time.Duration
	lastActive    common.TypedValue[time.Time]
	requestAccess sync.Mutex
	requests      map[pingRequest]int
	requestSlots  []trackedPingRequest
	requestHead   int
	requestTail   int
	requestFree   int
}

type pingRequest struct {
	Source      netip.Addr
	Destination netip.Addr
	Identifier  uint16
	Sequence    uint16
}

type trackedPingRequest struct {
	request   pingRequest
	createdAt time.Time
	previous  int
	next      int
}

func ConnectDestination(
	ctx context.Context,
	logger logger.ContextLogger,
	controlFunc control.Func,
	destination netip.Addr,
	writer PacketWriter,
	timeout time.Duration,
) (*Destination, error) {
	var (
		conn *Conn
		err  error
	)
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		conn, err = Connect(ctx, false, controlFunc, destination, timeout)
	default:
		conn, err = Connect(ctx, true, controlFunc, destination, timeout)
		if errors.Is(err, os.ErrPermission) {
			conn, err = Connect(ctx, false, controlFunc, destination, timeout)
		}
	}
	if err != nil {
		return nil, err
	}
	d := &Destination{
		conn:        conn,
		ctx:         ctx,
		logger:      logger,
		destination: destination,
		writer:      writer,
		timeout:     timeout,
		requests:    make(map[pingRequest]int),
		requestHead: -1,
		requestTail: -1,
		requestFree: -1,
	}
	d.lastActive.Store(time.Now())
	go d.loopRead()
	return d, nil
}

func (d *Destination) loopRead() {
	defer d.Close()
	for {
		deadline := d.lastActive.Load().Add(d.timeout)
		if !time.Now().Before(deadline) {
			return
		}
		err := d.conn.SetReadDeadline(deadline)
		if err != nil {
			d.logger.ErrorContext(d.ctx, E.Cause(err, "set read deadline for ICMP conn"))
		}
		buffer := buf.NewSize(maxICMPPacketSize)
		err = d.conn.ReadIP(buffer)
		if err != nil {
			buffer.Release()
			if E.IsTimeout(err) {
				continue
			}
			if !E.IsClosed(err) {
				d.logger.ErrorContext(d.ctx, E.Cause(err, "receive ICMP echo reply"))
			}
			return
		}
		if !d.destination.Is6() {
			ipHdr := header.IPv4(buffer.Bytes())
			if !ipHdr.IsValid(buffer.Len()) {
				d.logger.ErrorContext(d.ctx, E.New("invalid IPv4 header received"))
				continue
			}
			if ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
				d.logger.ErrorContext(d.ctx, E.New("invalid ICMPv4 header received"))
				continue
			}
			icmpHdr := header.ICMPv4(ipHdr.Payload())
			if d.needFilter() {
				switch icmpHdr.Type() {
				case header.ICMPv4EchoReply:
					request := pingRequest{Source: ipHdr.DestinationAddr(), Destination: ipHdr.SourceAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}
					d.requestAccess.Lock()
					loaded := d.removeRequest(request)
					d.requestAccess.Unlock()
					if !loaded {
						continue
					}
					d.logger.TraceContext(d.ctx, "read ICMPv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
				case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
					if !d.rewriteICMPv4Error(ipHdr, icmpHdr) {
						continue
					}
				default:
					continue
				}
			} else {
				d.logger.TraceContext(d.ctx, "read ICMPv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
			}
		} else {
			ipHdr := header.IPv6(buffer.Bytes())
			if !ipHdr.IsValid(buffer.Len()) {
				d.logger.ErrorContext(d.ctx, E.New("invalid IPv6 header received"))
				continue
			}
			if ipHdr.PayloadLength() < header.ICMPv6MinimumSize {
				d.logger.ErrorContext(d.ctx, E.New("invalid ICMPv6 header received"))
				continue
			}
			icmpHdr := header.ICMPv6(ipHdr.Payload())
			if d.needFilter() {
				if icmpHdr.Type() != header.ICMPv6EchoReply {
					continue
				}
				var requestExists bool
				request := pingRequest{Source: ipHdr.DestinationAddr(), Destination: ipHdr.SourceAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}
				d.requestAccess.Lock()
				requestExists = d.removeRequest(request)
				d.requestAccess.Unlock()
				if !requestExists {
					continue
				}
			}
			d.logger.TraceContext(d.ctx, "read ICMPv6 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
		}
		d.lastActive.Store(time.Now())
		err = d.writer.WritePacket(buffer.Bytes())
		if err != nil {
			d.logger.ErrorContext(d.ctx, E.Cause(err, "write ICMP echo reply"))
		}
		buffer.Release()
	}
}

func (d *Destination) WritePacket(packet *buf.Buffer) error {
	d.lastActive.Store(time.Now())
	if !d.destination.Is6() {
		ipHdr := header.IPv4(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv4 header")
		}
		if ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
			return E.New("invalid ICMPv4 header")
		}
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		if d.needFilter() {
			d.registerRequest(pingRequest{Source: ipHdr.SourceAddr(), Destination: ipHdr.DestinationAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()})
		}
		d.logger.TraceContext(d.ctx, "write ICMPv4 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
	} else {
		ipHdr := header.IPv6(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv6 header")
		}
		if ipHdr.PayloadLength() < header.ICMPv6MinimumSize {
			return E.New("invalid ICMPv6 header")
		}
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		if d.needFilter() {
			d.registerRequest(pingRequest{Source: ipHdr.SourceAddr(), Destination: ipHdr.DestinationAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()})
		}
		d.logger.TraceContext(d.ctx, "write ICMPv6 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
	}
	return d.conn.WriteIP(packet)
}

func (d *Destination) rewriteICMPv4Error(ipHdr header.IPv4, icmpHdr header.ICMPv4) bool {
	inner := icmpHdr.Payload()
	if len(inner) < header.IPv4MinimumSize {
		return false
	}
	innerIPHdr := header.IPv4(inner)
	headerLen := int(innerIPHdr.HeaderLength())
	if headerLen < header.IPv4MinimumSize || len(inner) < headerLen+header.ICMPv4MinimumSize {
		return false
	}
	if innerIPHdr.TransportProtocol() != header.ICMPv4ProtocolNumber {
		return false
	}
	innerICMP := header.ICMPv4(inner[headerLen:])
	if innerICMP.Type() != header.ICMPv4Echo {
		return false
	}
	originalIdent := ^innerICMP.Ident()
	request := pingRequest{
		Source:      ipHdr.DestinationAddr(),
		Destination: innerIPHdr.DestinationAddr(),
		Identifier:  originalIdent,
		Sequence:    innerICMP.Sequence(),
	}
	d.requestAccess.Lock()
	_, loaded := d.requests[request]
	d.requestAccess.Unlock()
	if !loaded {
		return false
	}
	innerICMP.SetIdent(originalIdent)
	innerICMP.SetChecksum(header.ICMPv4Checksum(innerICMP, 0))
	innerIPHdr.SetSourceAddr(ipHdr.DestinationAddr())
	innerIPHdr.SetChecksum(^innerIPHdr.CalculateChecksum())
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	d.logger.TraceContext(d.ctx, "read ICMPv4 error type ", int(icmpHdr.Type()), " from ", ipHdr.SourceAddr(), " seq ", innerICMP.Sequence())
	return true
}

func (d *Destination) needFilter() bool {
	return !d.conn.isLinuxUnprivileged()
}

func (d *Destination) registerRequest(request pingRequest) {
	d.requestAccess.Lock()
	defer d.requestAccess.Unlock()
	now := time.Now()
	d.pruneRequests(now)
	if existing, loaded := d.requests[request]; loaded {
		d.removeRequestAt(existing)
	}
	if len(d.requests) >= requestsLimit {
		d.removeRequestAt(d.requestHead)
	}
	var requestIndex int
	if d.requestFree >= 0 {
		requestIndex = d.requestFree
		d.requestFree = d.requestSlots[requestIndex].next
		d.requestSlots[requestIndex] = trackedPingRequest{
			request:   request,
			createdAt: now,
			previous:  d.requestTail,
			next:      -1,
		}
	} else {
		requestIndex = len(d.requestSlots)
		d.requestSlots = append(d.requestSlots, trackedPingRequest{
			request:   request,
			createdAt: now,
			previous:  d.requestTail,
			next:      -1,
		})
	}
	if d.requestTail >= 0 {
		d.requestSlots[d.requestTail].next = requestIndex
	} else {
		d.requestHead = requestIndex
	}
	d.requestTail = requestIndex
	d.requests[request] = requestIndex
}

func (d *Destination) pruneRequests(now time.Time) {
	for d.requestHead >= 0 && now.Sub(d.requestSlots[d.requestHead].createdAt) > d.timeout {
		d.removeRequestAt(d.requestHead)
	}
}

func (d *Destination) removeRequest(request pingRequest) bool {
	requestIndex, loaded := d.requests[request]
	if !loaded {
		return false
	}
	d.removeRequestAt(requestIndex)
	return true
}

func (d *Destination) removeRequestAt(requestIndex int) {
	trackedRequest := &d.requestSlots[requestIndex]
	if trackedRequest.previous >= 0 {
		d.requestSlots[trackedRequest.previous].next = trackedRequest.next
	} else {
		d.requestHead = trackedRequest.next
	}
	if trackedRequest.next >= 0 {
		d.requestSlots[trackedRequest.next].previous = trackedRequest.previous
	} else {
		d.requestTail = trackedRequest.previous
	}
	delete(d.requests, trackedRequest.request)
	trackedRequest.request = pingRequest{}
	trackedRequest.createdAt = time.Time{}
	trackedRequest.previous = -1
	trackedRequest.next = d.requestFree
	d.requestFree = requestIndex
}

func (d *Destination) Close() error {
	return d.conn.Close()
}

func (d *Destination) IsClosed() bool {
	return d.conn.IsClosed()
}

package kone

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	singtun "github.com/sagernet/sing-tun"
)

// Native gVisor endpoints read a platform FD/ReadFunc directly. A bounded
// channel bridge keeps full-gVisor reads and writes inside our failure and
// shutdown supervision, including on Windows. Queue occupancy is capped at
// 256 packets; overload drops packets rather than growing memory without bound.
type supervisedEndpoint struct {
	*channel.Endpoint
	tun     *gvisorTun
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	active  bool
	started bool
	stopped bool
	workers sync.WaitGroup
}

func newSupervisedEndpoint(tun *gvisorTun) *supervisedEndpoint {
	ctx, cancel := context.WithCancel(tun.ctx)
	return &supervisedEndpoint{Endpoint: channel.New(256, MTU, ""), tun: tun, ctx: ctx, cancel: cancel}
}

func (e *supervisedEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		e.stop()
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.Endpoint.Attach(dispatcher)
	e.startLocked()
}

// CreateNIC attaches its dispatcher before sing-tun finishes installing TCP/
// UDP handlers. Publish them completely before any queued TUN packet can enter
// netstack. Starting the workers after Start returns supplies happens-before.
func (e *supervisedEndpoint) activate() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.active = true
	e.startLocked()
}

func (e *supervisedEndpoint) startLocked() {
	if e.active && !e.started && e.Endpoint.IsAttached() {
		e.started = true
		e.workers.Add(2)
		go e.readLoop()
		go e.writeLoop()
	}
}

func (e *supervisedEndpoint) stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.stopped = true
	e.cancel()
	e.Endpoint.Attach(nil)
	e.Endpoint.Close()
}

// The owning engine closes the device before Wait, releasing any blocked Read.
func (e *supervisedEndpoint) Wait() { e.workers.Wait() }

func (e *supervisedEndpoint) readLoop() {
	defer e.workers.Done()
	packet := make([]byte, MTU+singtun.PacketOffset)
	var retry singtun.ReadRetry
	for e.ctx.Err() == nil {
		n, err := e.tun.Read(packet)
		if err != nil {
			if singtun.IsRecoverableReadError(err) {
				retry.Wait(err)
				continue
			}
			return // supervisedTun already reported terminal failure
		}
		retry.Reset()
		if n > len(packet) || n < 0 {
			e.tun.report(errors.New("TUN returned invalid packet length"))
			return
		}
		if n <= singtun.PacketOffset || e.ctx.Err() != nil {
			continue
		}
		raw := packet[singtun.PacketOffset:n]
		var protocol tcpip.NetworkProtocolNumber
		switch raw[0] >> 4 {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(raw)), IsForwardedPacket: true})
		// Filters may write the original packet back before netstack parses
		// it. Darwin's native WritePacket uses this field for the utun family
		// header, so passing only InjectInbound's protocol is insufficient.
		pkt.NetworkProtocolNumber = protocol
		e.Endpoint.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
}

func (e *supervisedEndpoint) writeLoop() {
	defer e.workers.Done()
	for {
		pkt := e.Endpoint.ReadContext(e.ctx)
		if pkt == nil {
			return
		}
		_, err := e.tun.WritePacket(pkt)
		pkt.DecRef()
		if err != nil {
			if singtun.IsRecoverableReadError(err) {
				// A transient nonblocking write drops this packet; TCP may
				// retransmit. Keep the writer alive for subsequent packets.
				continue
			}
			return // WritePacket reported failure without closing shared device
		}
	}
}

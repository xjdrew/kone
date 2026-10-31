//go:build with_gvisor

package tun

import (
	"errors"
	"syscall"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	gHdr "github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type Mixed struct {
	*System
	tun          GVisorTun
	stack        *stack.Stack
	endpoint     *channel.Endpoint
	udpForwarder *UDPForwarder
}

func NewMixed(
	options StackOptions,
) (Stack, error) {
	system, err := NewSystem(options)
	if err != nil {
		return nil, err
	}
	return &Mixed{
		System: system.(*System),
		tun:    system.(*System).tun.(GVisorTun),
	}, nil
}

func (m *Mixed) Start() error {
	err := m.System.start()
	if err != nil {
		return err
	}
	endpoint := channel.New(1024, uint32(m.mtu), "")
	ipStack, err := NewGVisorStack(endpoint)
	if err != nil {
		return err
	}
	udpForwarder := NewUDPForwarder(m.ctx, ipStack, m.handler, m.udpNATOptions)
	err = udpForwarder.Start()
	if err != nil {
		return err
	}
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	m.udpForwarder = udpForwarder
	m.stack = ipStack
	m.endpoint = endpoint
	go m.tunLoop()
	go m.packetLoop()
	return nil
}

func (m *Mixed) ResetNetwork() {
	m.System.ResetNetwork()
	if m.udpForwarder != nil {
		m.udpForwarder.udpNat.Purge()
	}
}

func (m *Mixed) Close() error {
	if m.stack == nil {
		return nil
	}
	if m.udpForwarder != nil {
		m.udpForwarder.Close()
	}
	m.endpoint.Attach(nil)
	m.stack.Close()
	for _, endpoint := range m.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	return m.System.Close()
}

func (m *Mixed) tunLoop() {
	if winTun, isWinTun := m.tun.(WinTun); isWinTun {
		m.wintunLoop(winTun)
		return
	}
	if linuxTUN, isLinuxTUN := m.tun.(LinuxTUN); isLinuxTUN {
		batchSize := linuxTUN.BatchSize()
		if batchSize > 1 {
			m.batchLoopLinux(linuxTUN, batchSize)
			return
		}
	}
	if darwinTUN, isDarwinTUN := m.tun.(DarwinTUN); isDarwinTUN && m.multiPendingPackets {
		m.batchLoopDarwin(darwinTUN)
		return
	}
	packetBuffer := make([]byte, m.mtu+PacketOffset)
	var readRetry ReadRetry
	for {
		n, err := m.tun.Read(packetBuffer)
		if err != nil {
			if IsRecoverableReadError(err) {
				m.logger.Debug(E.Cause(err, "read packet"))
				readRetry.Wait(err)
				continue
			}
			if !E.IsClosed(err) {
				m.logger.Error(E.Cause(err, "read packet"))
			}
			return
		}
		readRetry.Reset()
		if n-PacketOffset < header.IPv4MinimumSize {
			continue
		}
		rawPacket := packetBuffer[:n]
		packet := packetBuffer[PacketOffset:n]
		if m.processPacket(packet) {
			_, err = m.tun.Write(rawPacket)
			if err != nil {
				m.logger.Trace(E.Cause(err, "write packet"))
			}
		}
		m.dispatcher.Flush()
	}
}

func (m *Mixed) wintunLoop(winTun WinTun) {
	for {
		packet, release, err := winTun.ReadPacket()
		if err != nil {
			return
		}
		if len(packet) < header.IPv4MinimumSize {
			release()
			continue
		}
		if m.processPacket(packet) {
			_, err = winTun.Write(packet)
			if err != nil {
				m.logger.Trace(E.Cause(err, "write packet"))
			}
		}
		m.dispatcher.Flush()
		release()
	}
}

func (m *Mixed) batchLoopLinux(linuxTUN LinuxTUN, batchSize int) {
	packetBuffers := make([][]byte, batchSize)
	writeBuffers := make([][]byte, 0, batchSize)
	packetSizes := make([]int, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = make([]byte, m.mtu+PacketOffset+m.frontHeadroom)
	}
	var readRetry ReadRetry
	for {
		n, err := linuxTUN.BatchRead(packetBuffers, m.frontHeadroom, packetSizes)
		if err != nil {
			if !IsRecoverableReadError(err) {
				if !E.IsClosed(err) {
					m.logger.Error(E.Cause(err, "batch read packet"))
				}
				return
			}
			m.logger.Debug(E.Cause(err, "batch read packet"))
			readRetry.Wait(err)
		} else {
			readRetry.Reset()
		}
		if n == 0 {
			continue
		}
		for i := 0; i < n; i++ {
			packetSize := packetSizes[i]
			if packetSize < header.IPv4MinimumSize {
				continue
			}
			packetBuffer := packetBuffers[i]
			packet := packetBuffer[m.frontHeadroom : m.frontHeadroom+packetSize]
			if m.processPacket(packet) {
				writeBuffers = append(writeBuffers, packetBuffer[:m.frontHeadroom+packetSize])
			}
		}
		if len(writeBuffers) > 0 {
			_, err = linuxTUN.BatchWrite(writeBuffers, m.frontHeadroom)
			if err != nil {
				m.logger.Trace(E.Cause(err, "batch write packet"))
			}
			writeBuffers = writeBuffers[:0]
		}
		m.dispatcher.Flush()
	}
}

func (m *Mixed) batchLoopDarwin(darwinTUN DarwinTUN) {
	var writeBuffers []*buf.Buffer
	var releaseBuffers []*buf.Buffer
	var readRetry ReadRetry
	for {
		buffers, err := darwinTUN.BatchRead()
		if err != nil {
			if !IsRecoverableReadError(err) {
				if !E.IsClosed(err) && !errors.Is(err, syscall.EBADF) {
					m.logger.Error(E.Cause(err, "batch read packet"))
				}
				return
			}
			m.logger.Debug(E.Cause(err, "batch read packet"))
			readRetry.Wait(err)
		} else {
			readRetry.Reset()
		}
		if len(buffers) == 0 {
			continue
		}
		writeBuffers = writeBuffers[:0]
		releaseBuffers = releaseBuffers[:0]
		for _, buffer := range buffers {
			packetSize := buffer.Len()
			if packetSize < header.IPv4MinimumSize {
				buffer.Release()
				continue
			}
			if m.processPacket(buffer.Bytes()) {
				writeBuffers = append(writeBuffers, buffer)
			} else {
				releaseBuffers = append(releaseBuffers, buffer)
			}
		}
		if len(writeBuffers) > 0 {
			err = darwinTUN.BatchWrite(writeBuffers)
			if err != nil {
				m.logger.Trace(E.Cause(err, "batch write packet"))
			}
			buf.ReleaseMulti(writeBuffers)
		}
		m.dispatcher.Flush()
		buf.ReleaseMulti(releaseBuffers)
	}
}

func (m *Mixed) processPacket(packet []byte) bool {
	var (
		writeBack bool
		err       error
	)
	switch ipVersion := header.IPVersion(packet); ipVersion {
	case header.IPv4Version:
		writeBack, err = m.processIPv4(packet)
	case header.IPv6Version:
		writeBack, err = m.processIPv6(packet)
	default:
		err = E.New("ip: unknown version: ", ipVersion)
	}
	if err != nil {
		m.logger.Trace(err)
		return false
	}
	return writeBack
}

func (m *Mixed) processIPv4(ipHdr header.IPv4) (writeBack bool, err error) {
	if !ipHdr.IsValid(len(ipHdr)) {
		return false, E.New("ipv4: invalid packet")
	}
	ipHdr = ipHdr[:ipHdr.TotalLength()]
	writeBack = true
	destination := ipHdr.DestinationAddr()
	if destination == m.broadcastAddr || !destination.IsGlobalUnicast() {
		return
	}
	if m.dispatchIPv4(ipHdr, destination) {
		return false, nil
	}
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = m.processIPv4TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(ipHdr),
			IsForwardedPacket: true,
		})
		m.endpoint.InjectInbound(gHdr.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
		return
	case header.ICMPv4ProtocolNumber:
		writeBack, err = m.processIPv4ICMP(ipHdr, ipHdr.Payload())
	}
	return
}

func (m *Mixed) processIPv6(ipHdr header.IPv6) (writeBack bool, err error) {
	if !ipHdr.IsValid(len(ipHdr)) {
		return false, E.New("ipv6: invalid packet")
	}
	ipHdr = ipHdr[:header.IPv6MinimumSize+int(ipHdr.PayloadLength())]
	writeBack = true
	destination := ipHdr.DestinationAddr()
	if !destination.IsGlobalUnicast() {
		return
	}
	if m.dispatchIPv6(ipHdr, destination) {
		return false, nil
	}
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = m.processIPv6TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(ipHdr),
			IsForwardedPacket: true,
		})
		m.endpoint.InjectInbound(tcpip.NetworkProtocolNumber(header.IPv6ProtocolNumber), pkt)
		pkt.DecRef()
	case header.ICMPv6ProtocolNumber:
		writeBack, err = m.processIPv6ICMP(ipHdr, ipHdr.Payload())
	}
	return
}

func (m *Mixed) packetLoop() {
	for {
		pkt := m.endpoint.ReadContext(m.ctx)
		if pkt == nil {
			break
		}
		m.tun.WritePacket(pkt)
		pkt.DecRef()
	}
}

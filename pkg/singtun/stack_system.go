package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrIncludeAllNetworks = E.New("`system` and `mixed` stack are not available when `includeAllNetworks` is enabled. See https://github.com/SagerNet/sing-tun/issues/25")

type System struct {
	ctx                  context.Context
	tun                  Tun
	tunName              string
	netNs                string
	mtu                  int
	handler              Handler
	logger               logger.Logger
	inet4Prefixes        []netip.Prefix
	inet6Prefixes        []netip.Prefix
	inet4Address         netip.Addr
	inet4NextAddress     netip.Addr
	inet6Address         netip.Addr
	inet6NextAddress     netip.Addr
	broadcastAddr        netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	udpTimeout           time.Duration
	icmpTimeout          time.Duration
	tcpListener          net.Listener
	tcpListener6         net.Listener
	tcpPort              uint16
	tcpPort6             uint16
	tcpNat4              *TCPNat
	tcpNat6              *TCPNat
	udpNat               *UDPNat
	udpNATOptions        UDPNatOptions
	dispatcher           *ForwardDispatcher
	bindInterface        bool
	interfaceFinder      control.InterfaceFinder
	frontHeadroom        int
	txChecksumOffload    bool
	multiPendingPackets  bool
}

type Session struct {
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
	SourcePort         uint16
	DestinationPort    uint16
}

func NewSystem(options StackOptions) (Stack, error) {
	stack := &System{
		ctx:                  options.Context,
		tun:                  options.Tun,
		tunName:              options.TunOptions.Name,
		netNs:                options.TunOptions.NetNs,
		mtu:                  int(options.TunOptions.MTU),
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		udpTimeout:           options.UDPTimeout,
		icmpTimeout:          options.ICMPTimeout,
		handler:              options.Handler,
		logger:               options.Logger,
		inet4Prefixes:        options.TunOptions.Inet4Address,
		inet6Prefixes:        options.TunOptions.Inet6Address,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		udpNATOptions: UDPNatOptions{
			Timeout:          options.UDPTimeout,
			Mapping:          options.UDPMapping,
			Filtering:        options.UDPFiltering,
			MaxSize:          options.UDPNATMax,
			InterfaceFinder:  options.InterfaceFinder,
			ExcludeInterface: []string{options.TunOptions.Name},
		},
		bindInterface:       options.ForwarderBindInterface,
		interfaceFinder:     options.InterfaceFinder,
		multiPendingPackets: options.TunOptions.EXP_MultiPendingPackets,
	}
	if len(options.TunOptions.Inet4Address) > 0 {
		if !HasNextAddress(options.TunOptions.Inet4Address[0], 1) {
			return nil, E.New("need one more IPv4 address in first prefix for system stack")
		}
		stack.inet4Address = options.TunOptions.Inet4Address[0].Addr()
		stack.inet4NextAddress = stack.inet4Address.Next()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		if !HasNextAddress(options.TunOptions.Inet6Address[0], 1) {
			return nil, E.New("need one more IPv6 address in first prefix for system stack")
		}
		stack.inet6Address = options.TunOptions.Inet6Address[0].Addr()
		stack.inet6NextAddress = stack.inet6Address.Next()
	}
	if !stack.inet4NextAddress.IsValid() && !stack.inet6NextAddress.IsValid() {
		return nil, E.New("missing interface address")
	}
	return stack, nil
}

func (s *System) ResetNetwork() {
	if s.udpNat != nil {
		s.udpNat.Purge()
	}
	s.dispatcher.ResetNetwork()
}

func (s *System) Close() error {
	s.dispatcher.Close()
	if s.udpNat != nil {
		s.udpNat.Close()
	}
	return common.Close(
		s.tcpListener,
		s.tcpListener6,
	)
}

func (s *System) Start() error {
	err := s.start()
	if err != nil {
		return err
	}
	go s.tunLoop()
	return nil
}

func (s *System) start() error {
	_ = fixWindowsFirewall()
	var listener net.ListenConfig
	if s.bindInterface {
		listener.Control = control.Append(listener.Control, func(network, address string, conn syscall.RawConn) error {
			bindErr := control.BindToInterface0(s.interfaceFinder, conn, network, address, s.tunName, -1, true)
			if bindErr != nil {
				s.logger.Warn("bind forwarder to interface: ", bindErr)
			}
			return nil
		})
	}
	var tcpListener net.Listener
	var err error
	if s.inet4NextAddress.IsValid() {
		for range 3 {
			tcpListener, err = listenNetworkNamespace(s.ctx, s.netNs, listener, "tcp4", net.JoinHostPort(s.inet4Address.String(), "0"))
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		s.tcpListener = tcpListener
		s.tcpPort = M.SocksaddrFromNet(tcpListener.Addr()).Port
		s.tcpNat4 = NewNat(s.ctx, s.udpTimeout)
		go s.acceptLoop(tcpListener, s.tcpNat4)
	}
	if s.inet6NextAddress.IsValid() {
		for range 3 {
			tcpListener, err = listenNetworkNamespace(s.ctx, s.netNs, listener, "tcp6", net.JoinHostPort(s.inet6Address.String(), "0"))
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		s.tcpListener6 = tcpListener
		s.tcpPort6 = M.SocksaddrFromNet(tcpListener.Addr()).Port
		s.tcpNat6 = NewNat(s.ctx, s.udpTimeout)
		go s.acceptLoop(tcpListener, s.tcpNat6)
	}
	udpNATOptions := s.udpNATOptions
	udpNATOptions.Handler = s.handler
	udpNATOptions.Prepare = s.preparePacketConnection
	s.udpNat = NewUDPNat(udpNATOptions)
	err = s.udpNat.Start()
	if err != nil {
		return err
	}
	if linuxTUN, isLinuxTUN := s.tun.(LinuxTUN); isLinuxTUN {
		s.frontHeadroom = linuxTUN.FrontHeadroom()
		s.txChecksumOffload = linuxTUN.TXChecksumOffload()
	}
	if s.handler != nil {
		s.dispatcher = NewForwardDispatcher(s.handler, newSystemWriteback(s.tun, s.frontHeadroom), s.logger, s.udpTimeout, s.icmpTimeout)
	}
	return nil
}

func (s *System) tunLoop() {
	if winTun, isWinTun := s.tun.(WinTun); isWinTun {
		s.wintunLoop(winTun)
		return
	}
	if linuxTUN, isLinuxTUN := s.tun.(LinuxTUN); isLinuxTUN {
		batchSize := linuxTUN.BatchSize()
		if batchSize > 1 {
			s.batchLoopLinux(linuxTUN, batchSize)
			return
		}
	}
	if darwinTUN, isDarwinTUN := s.tun.(DarwinTUN); isDarwinTUN && s.multiPendingPackets {
		s.batchLoopDarwin(darwinTUN)
		return
	}
	packetBuffer := make([]byte, s.mtu+PacketOffset)
	var readRetry ReadRetry
	for {
		n, err := s.tun.Read(packetBuffer)
		if err != nil {
			if IsRecoverableReadError(err) {
				s.logger.Debug(E.Cause(err, "read packet"))
				readRetry.Wait(err)
				continue
			}
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "read packet"))
			}
			return
		}
		readRetry.Reset()
		if n-PacketOffset < header.IPv4MinimumSize {
			continue
		}
		rawPacket := packetBuffer[:n]
		packet := packetBuffer[PacketOffset:n]
		if s.processPacket(packet) {
			_, err = s.tun.Write(rawPacket)
			if err != nil {
				s.logger.Trace(E.Cause(err, "write packet"))
			}
		}
		s.dispatcher.Flush()
	}
}

func (s *System) wintunLoop(winTun WinTun) {
	for {
		packet, release, err := winTun.ReadPacket()
		if err != nil {
			return
		}
		if len(packet) < header.IPv4MinimumSize {
			release()
			continue
		}
		if s.processPacket(packet) {
			_, err = winTun.Write(packet)
			if err != nil {
				s.logger.Trace(E.Cause(err, "write packet"))
			}
		}
		s.dispatcher.Flush()
		release()
	}
}

func (s *System) batchLoopLinux(linuxTUN LinuxTUN, batchSize int) {
	packetBuffers := make([][]byte, batchSize)
	writeBuffers := make([][]byte, 0, batchSize)
	packetSizes := make([]int, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = make([]byte, s.mtu+s.frontHeadroom)
	}
	var readRetry ReadRetry
	for {
		n, err := linuxTUN.BatchRead(packetBuffers, s.frontHeadroom, packetSizes)
		if err != nil {
			if !IsRecoverableReadError(err) {
				if !E.IsClosed(err) {
					s.logger.Error(E.Cause(err, "batch read packet"))
				}
				return
			}
			s.logger.Debug(E.Cause(err, "batch read packet"))
			readRetry.Wait(err)
		} else {
			readRetry.Reset()
		}
		if n == 0 {
			continue
		}
		for i := range n {
			packetSize := packetSizes[i]
			if packetSize < header.IPv4MinimumSize {
				continue
			}
			packetBuffer := packetBuffers[i]
			packet := packetBuffer[s.frontHeadroom : s.frontHeadroom+packetSize]
			if s.processPacket(packet) {
				writeBuffers = append(writeBuffers, packetBuffer[:s.frontHeadroom+packetSize])
			}
		}
		if len(writeBuffers) > 0 {
			_, err = linuxTUN.BatchWrite(writeBuffers, s.frontHeadroom)
			if err != nil {
				s.logger.Trace(E.Cause(err, "batch write packet"))
			}
			writeBuffers = writeBuffers[:0]
		}
		s.dispatcher.Flush()
	}
}

func (s *System) batchLoopDarwin(darwinTUN DarwinTUN) {
	var writeBuffers []*buf.Buffer
	var releaseBuffers []*buf.Buffer
	var readRetry ReadRetry
	for {
		buffers, err := darwinTUN.BatchRead()
		if err != nil {
			if !IsRecoverableReadError(err) {
				if !E.IsClosed(err) && !errors.Is(err, syscall.EBADF) {
					s.logger.Error(E.Cause(err, "batch read packet"))
				}
				return
			}
			s.logger.Debug(E.Cause(err, "batch read packet"))
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
			if s.processPacket(buffer.Bytes()) {
				writeBuffers = append(writeBuffers, buffer)
			} else {
				releaseBuffers = append(releaseBuffers, buffer)
			}
		}
		if len(writeBuffers) > 0 {
			err = darwinTUN.BatchWrite(writeBuffers)
			if err != nil {
				s.logger.Trace(E.Cause(err, "batch write packet"))
			}
			buf.ReleaseMulti(writeBuffers)
		}
		s.dispatcher.Flush()
		buf.ReleaseMulti(releaseBuffers)
	}
}

func (s *System) processPacket(packet []byte) bool {
	var (
		writeBack bool
		err       error
	)
	switch ipVersion := header.IPVersion(packet); ipVersion {
	case header.IPv4Version:
		writeBack, err = s.processIPv4(packet)
	case header.IPv6Version:
		writeBack, err = s.processIPv6(packet)
	default:
		err = E.New("ip: unknown version: ", ipVersion)
	}
	if err != nil {
		s.logger.Trace(err)
		return false
	}
	return writeBack
}

func (s *System) acceptLoop(listener net.Listener, tcpNat *TCPNat) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connPort := M.SocksaddrFromNet(conn.RemoteAddr()).Port
		session := tcpNat.LookupBack(connPort, 0)
		if session == nil {
			s.logger.Trace(E.New("unknown session with port ", connPort))
			continue
		}
		go s.handler.NewConnectionEx(s.ctx, conn, M.SocksaddrFromNetIP(session.Source), M.SocksaddrFromNetIP(session.Destination), nil)
	}
}

func (s *System) dispatchIPv4(ipHdr header.IPv4, destination netip.Addr) bool {
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		if slices.Contains(s.inet4LoopbackAddress, destination) {
			return false
		}
		if ipHdr.SourceAddr() == s.inet4Address &&
			ipHdr.FragmentOffset() == 0 &&
			len(ipHdr.Payload()) >= header.TCPMinimumSize &&
			header.TCP(ipHdr.Payload()).SourcePort() == s.tcpPort {
			return false
		}
	case header.ICMPv4ProtocolNumber:
		if destination == s.inet4Address {
			return false
		}
	}
	return s.dispatcher.Dispatch(ipHdr)
}

func (s *System) dispatchIPv6(ipHdr header.IPv6, destination netip.Addr) bool {
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		if slices.Contains(s.inet6LoopbackAddress, destination) {
			return false
		}
		if ipHdr.SourceAddr() == s.inet6Address &&
			len(ipHdr.Payload()) >= header.TCPMinimumSize &&
			header.TCP(ipHdr.Payload()).SourcePort() == s.tcpPort6 {
			return false
		}
	case header.ICMPv6ProtocolNumber:
		if destination == s.inet6Address {
			return false
		}
	}
	return s.dispatcher.Dispatch(ipHdr)
}

func (s *System) processIPv4(ipHdr header.IPv4) (writeBack bool, err error) {
	if !ipHdr.IsValid(len(ipHdr)) {
		return false, E.New("ipv4: invalid packet")
	}
	ipHdr = ipHdr[:ipHdr.TotalLength()]
	destination := ipHdr.DestinationAddr()
	if destination == s.broadcastAddr || !destination.IsGlobalUnicast() {
		return
	}
	if s.dispatchIPv4(ipHdr, destination) {
		return false, nil
	}
	writeBack = true
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = s.processIPv4TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		err = s.processIPv4UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv4ProtocolNumber:
		writeBack, err = s.processIPv4ICMP(ipHdr, ipHdr.Payload())
	}
	if err != nil {
		writeBack = false
	}
	return
}

func (s *System) processIPv6(ipHdr header.IPv6) (writeBack bool, err error) {
	if !ipHdr.IsValid(len(ipHdr)) {
		return false, E.New("ipv6: invalid packet")
	}
	ipHdr = ipHdr[:header.IPv6MinimumSize+int(ipHdr.PayloadLength())]
	destination := ipHdr.DestinationAddr()
	if !destination.IsGlobalUnicast() {
		return
	}
	if s.dispatchIPv6(ipHdr, destination) {
		return false, nil
	}
	writeBack = true
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = s.processIPv6TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		err = s.processIPv6UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv6ProtocolNumber:
		writeBack, err = s.processIPv6ICMP(ipHdr, ipHdr.Payload())
	}
	if err != nil {
		writeBack = false
	}
	return
}

func (s *System) processIPv4TCP(ipHdr header.IPv4, tcpHdr header.TCP) (bool, error) {
	if s.tcpNat4 == nil {
		return false, nil
	}
	if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 || ipHdr.FragmentOffset() != 0 {
		return false, E.New("ipv4: tcp: fragment dropped")
	}
	if len(tcpHdr) < header.TCPMinimumSize || int(tcpHdr.DataOffset()) < header.TCPMinimumSize || int(tcpHdr.DataOffset()) > len(tcpHdr) {
		return false, E.New("ipv4: tcp: invalid packet")
	}
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return false, nil
	} else if source.Addr() == s.inet4Address && source.Port() == s.tcpPort {
		session := s.tcpNat4.LookupBack(destination.Port(), tcpHdr.Flags())
		if session == nil {
			return false, E.New("ipv4: tcp: session not found: ", destination.Port())
		}
		rewriteIPv4TCP(ipHdr, tcpHdr, s.txChecksumOffload,
			session.Destination.Addr(), session.Destination.Port(), true,
			session.Source.Addr(), session.Source.Port(), true)
	} else {
		var loopback bool
		for _, inet4LoopbackAddress := range s.inet4LoopbackAddress {
			if destination.Addr() == inet4LoopbackAddress {
				rewriteIPv4TCP(ipHdr, tcpHdr, s.txChecksumOffload,
					inet4LoopbackAddress, 0, false,
					source.Addr(), 0, false)
				loopback = true
				break
			}
		}
		if !loopback {
			natPort := s.tcpNat4.Lookup(source, destination, tcpHdr.Flags())
			if natPort == 0 {
				return false, E.New("ipv4: tcp: NAT port space exhausted")
			}
			rewriteIPv4TCP(ipHdr, tcpHdr, s.txChecksumOffload,
				s.inet4NextAddress, natPort, true,
				s.inet4Address, s.tcpPort, true)
		}
	}
	return true, nil
}

func (s *System) processIPv6TCP(ipHdr header.IPv6, tcpHdr header.TCP) (bool, error) {
	if s.tcpNat6 == nil {
		return false, nil
	}
	if len(tcpHdr) < header.TCPMinimumSize || int(tcpHdr.DataOffset()) < header.TCPMinimumSize || int(tcpHdr.DataOffset()) > len(tcpHdr) {
		return false, E.New("ipv6: tcp: invalid packet")
	}
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return false, nil
	} else if source.Addr() == s.inet6Address && source.Port() == s.tcpPort6 {
		session := s.tcpNat6.LookupBack(destination.Port(), tcpHdr.Flags())
		if session == nil {
			return false, E.New("ipv6: tcp: session not found: ", destination.Port())
		}
		rewriteIPv6TCP(ipHdr, tcpHdr, s.txChecksumOffload,
			session.Destination.Addr(), session.Destination.Port(), true,
			session.Source.Addr(), session.Source.Port(), true)
	} else {
		var loopback bool
		for _, inet6LoopbackAddress := range s.inet6LoopbackAddress {
			if destination.Addr() == inet6LoopbackAddress {
				rewriteIPv6TCP(ipHdr, tcpHdr, s.txChecksumOffload,
					inet6LoopbackAddress, 0, false,
					source.Addr(), 0, false)
				loopback = true
				break
			}
		}
		if !loopback {
			natPort := s.tcpNat6.Lookup(source, destination, tcpHdr.Flags())
			if natPort == 0 {
				return false, E.New("ipv6: tcp: NAT port space exhausted")
			}
			rewriteIPv6TCP(ipHdr, tcpHdr, s.txChecksumOffload,
				s.inet6NextAddress, natPort, true,
				s.inet6Address, s.tcpPort6, true)
		}
	}
	return true, nil
}

func rewriteIPv4TCP(ipHdr header.IPv4, tcpHdr header.TCP, txChecksumOffload bool,
	newSource netip.Addr, newSourcePort uint16, rewriteSourcePort bool,
	newDestination netip.Addr, newDestinationPort uint16, rewriteDestinationPort bool,
) {
	oldSource := ipHdr.SourceAddress()
	oldDestination := ipHdr.DestinationAddress()
	newSourceAddr := tcpip.AddrFrom4(newSource.As4())
	newDestinationAddr := tcpip.AddrFrom4(newDestination.As4())
	if newSourceAddr != oldSource {
		ipHdr.SetSourceAddressWithChecksumUpdate(newSourceAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldSource, newSourceAddr, true)
		}
	}
	if newDestinationAddr != oldDestination {
		ipHdr.SetDestinationAddressWithChecksumUpdate(newDestinationAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldDestination, newDestinationAddr, true)
		}
	}
	if txChecksumOffload {
		if rewriteSourcePort {
			tcpHdr.SetSourcePort(newSourcePort)
		}
		if rewriteDestinationPort {
			tcpHdr.SetDestinationPort(newDestinationPort)
		}
		tcpHdr.SetChecksum(0)
	} else {
		if rewriteSourcePort {
			tcpHdr.SetSourcePortWithChecksumUpdate(newSourcePort)
		}
		if rewriteDestinationPort {
			tcpHdr.SetDestinationPortWithChecksumUpdate(newDestinationPort)
		}
	}
}

func rewriteIPv6TCP(ipHdr header.IPv6, tcpHdr header.TCP, txChecksumOffload bool,
	newSource netip.Addr, newSourcePort uint16, rewriteSourcePort bool,
	newDestination netip.Addr, newDestinationPort uint16, rewriteDestinationPort bool,
) {
	oldSource := ipHdr.SourceAddress()
	oldDestination := ipHdr.DestinationAddress()
	newSourceAddr := tcpip.AddrFrom16(newSource.As16())
	newDestinationAddr := tcpip.AddrFrom16(newDestination.As16())
	if newSourceAddr != oldSource {
		ipHdr.SetSourceAddress(newSourceAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldSource, newSourceAddr, true)
		}
	}
	if newDestinationAddr != oldDestination {
		ipHdr.SetDestinationAddress(newDestinationAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldDestination, newDestinationAddr, true)
		}
	}
	if txChecksumOffload {
		if rewriteSourcePort {
			tcpHdr.SetSourcePort(newSourcePort)
		}
		if rewriteDestinationPort {
			tcpHdr.SetDestinationPort(newDestinationPort)
		}
		tcpHdr.SetChecksum(0)
	} else {
		if rewriteSourcePort {
			tcpHdr.SetSourcePortWithChecksumUpdate(newSourcePort)
		}
		if rewriteDestinationPort {
			tcpHdr.SetDestinationPortWithChecksumUpdate(newDestinationPort)
		}
	}
}

func (s *System) processIPv4UDP(ipHdr header.IPv4, udpHdr header.UDP) error {
	if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 || ipHdr.FragmentOffset() != 0 {
		return E.New("ipv4: fragment dropped")
	}
	if len(udpHdr) < header.UDPMinimumSize {
		return E.New("ipv4: udp: invalid packet")
	}
	source := M.SocksaddrFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := M.SocksaddrFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr.IsGlobalUnicast() {
		return nil
	}
	s.udpNat.NewPacket([][]byte{udpHdr.Payload()}, source, destination, ipHdr)
	return nil
}

func (s *System) processIPv6UDP(ipHdr header.IPv6, udpHdr header.UDP) error {
	if len(udpHdr) < header.UDPMinimumSize {
		return E.New("ipv6: udp: invalid packet")
	}
	source := M.SocksaddrFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := M.SocksaddrFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr.IsGlobalUnicast() {
		return nil
	}
	s.udpNat.NewPacket([][]byte{udpHdr.Payload()}, source, destination, ipHdr)
	return nil
}

func (s *System) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	var writer N.PacketWriter
	if source.IsIPv4() {
		packet := userData.(header.IPv4)
		headerLen := packet.HeaderLength() + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, packet[:headerLen])
		writer = &systemUDPPacketWriter4{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source.AddrPort(),
			s.txChecksumOffload,
		}
	} else {
		packet := userData.(header.IPv6)
		headerLen := len(packet) - int(packet.PayloadLength()) + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, packet[:headerLen])
		writer = &systemUDPPacketWriter6{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source.AddrPort(),
			s.txChecksumOffload,
		}
	}
	return true, s.ctx, writer, nil
}

func (s *System) processIPv4ICMP(ipHdr header.IPv4, icmpHdr header.ICMPv4) (bool, error) {
	if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 || ipHdr.FragmentOffset() != 0 {
		return false, E.New("ipv4: icmp: fragment dropped")
	}
	if len(icmpHdr) < header.ICMPv4MinimumSize {
		return false, E.New("ipv4: icmp: invalid packet")
	}
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return false, nil
	}
	icmpHdr.SetType(header.ICMPv4EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return true, nil
}

func (s *System) processIPv6ICMP(ipHdr header.IPv6, icmpHdr header.ICMPv6) (bool, error) {
	if len(icmpHdr) < header.ICMPv6MinimumSize {
		return false, E.New("ipv6: icmp: invalid packet")
	}
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return false, nil
	}
	icmpHdr.SetType(header.ICMPv6EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddressSlice(),
		Dst:    ipHdr.DestinationAddressSlice(),
	}))
	return true, nil
}

type systemUDPPacketWriter4 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter4) FrontHeadroom() int {
	return w.frontHeadroom + len(w.header)
}

func (w *systemUDPPacketWriter4) preparePacket(buffer *buf.Buffer, destination M.Socksaddr) *buf.Buffer {
	payloadLen := buffer.Len()
	buffer = (N.ReadWaitOptions{FrontHeadroom: w.FrontHeadroom()}).Copy(buffer)
	copy(buffer.ExtendHeader(len(w.header)), w.header)
	ipHdr := header.IPv4(buffer.Bytes())
	ipHdr.SetTotalLength(uint16(buffer.Len()))
	ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(uint16(payloadLen + header.UDPMinimumSize))
	if !w.txChecksumOffload {
		udpChecksum := ^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		))
		if udpChecksum == 0 {
			udpChecksum = 0xffff
		}
		udpHdr.SetChecksum(udpChecksum)
	} else {
		udpHdr.SetChecksum(0)
	}
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return buffer
}

func (w *systemUDPPacketWriter4) prepareWritePacket(buffer *buf.Buffer, destination M.Socksaddr) *buf.Buffer {
	buffer = w.preparePacket(buffer, destination)
	if PacketOffset > 0 {
		PacketFillHeader(buffer.ExtendHeader(PacketOffset), header.IPv4Version)
	}
	if remainingHeadroom := w.frontHeadroom - PacketOffset; remainingHeadroom > 0 {
		buffer.Advance(-remainingHeadroom)
	}
	return buffer
}

func (w *systemUDPPacketWriter4) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer = w.prepareWritePacket(buffer, destination)
	defer buffer.Release()
	return common.Error(w.tun.Write(buffer.Bytes()))
}

func (w *systemUDPPacketWriter4) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	switch w.tun.(type) {
	case LinuxTUN, DarwinTUN:
		return w, true
	default:
		return nil, false
	}
}

func (w *systemUDPPacketWriter4) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	defer func() {
		buf.ReleaseMulti(buffers)
	}()
	switch tunInterface := w.tun.(type) {
	case LinuxTUN:
		packets := make([][]byte, len(buffers))
		for index, buffer := range buffers {
			buffer = w.preparePacket(buffer, destinations[index])
			buffer.Advance(-w.frontHeadroom)
			buffers[index] = buffer
			packets[index] = buffer.Bytes()
		}
		return common.Error(tunInterface.BatchWrite(packets, w.frontHeadroom))
	case DarwinTUN:
		for index, buffer := range buffers {
			buffers[index] = w.preparePacket(buffer, destinations[index])
		}
		return tunInterface.BatchWrite(buffers)
	default:
		return os.ErrInvalid
	}
}

type systemUDPPacketWriter6 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter6) FrontHeadroom() int {
	return w.frontHeadroom + len(w.header)
}

func (w *systemUDPPacketWriter6) preparePacket(buffer *buf.Buffer, destination M.Socksaddr) *buf.Buffer {
	payloadLen := buffer.Len()
	buffer = (N.ReadWaitOptions{FrontHeadroom: w.FrontHeadroom()}).Copy(buffer)
	copy(buffer.ExtendHeader(len(w.header)), w.header)
	ipHdr := header.IPv6(buffer.Bytes())
	udpLen := uint16(header.UDPMinimumSize + payloadLen)
	ipHdr.SetPayloadLength(udpLen)
	ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLen)
	if !w.txChecksumOffload {
		udpChecksum := ^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		))
		if udpChecksum == 0 {
			udpChecksum = 0xffff
		}
		udpHdr.SetChecksum(udpChecksum)
	} else {
		udpHdr.SetChecksum(0)
	}
	return buffer
}

func (w *systemUDPPacketWriter6) prepareWritePacket(buffer *buf.Buffer, destination M.Socksaddr) *buf.Buffer {
	buffer = w.preparePacket(buffer, destination)
	if PacketOffset > 0 {
		PacketFillHeader(buffer.ExtendHeader(PacketOffset), header.IPv6Version)
	}
	if remainingHeadroom := w.frontHeadroom - PacketOffset; remainingHeadroom > 0 {
		buffer.Advance(-remainingHeadroom)
	}
	return buffer
}

func (w *systemUDPPacketWriter6) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer = w.prepareWritePacket(buffer, destination)
	defer buffer.Release()
	return common.Error(w.tun.Write(buffer.Bytes()))
}

func (w *systemUDPPacketWriter6) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	switch w.tun.(type) {
	case LinuxTUN, DarwinTUN:
		return w, true
	default:
		return nil, false
	}
}

func (w *systemUDPPacketWriter6) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	defer func() {
		buf.ReleaseMulti(buffers)
	}()
	switch tunInterface := w.tun.(type) {
	case LinuxTUN:
		packets := make([][]byte, len(buffers))
		for index, buffer := range buffers {
			buffer = w.preparePacket(buffer, destinations[index])
			buffer.Advance(-w.frontHeadroom)
			buffers[index] = buffer
			packets[index] = buffer.Bytes()
		}
		return common.Error(tunInterface.BatchWrite(packets, w.frontHeadroom))
	case DarwinTUN:
		for index, buffer := range buffers {
			buffers[index] = w.preparePacket(buffer, destinations[index])
		}
		return tunInterface.BatchWrite(buffers)
	default:
		return os.ErrInvalid
	}
}

func newSystemWriteback(tunInterface Tun, frontHeadroom int) ForwardWriteback {
	if linuxTUN, isLinuxTUN := tunInterface.(LinuxTUN); isLinuxTUN {
		return &systemWritebackLinux{linuxTUN: linuxTUN, frontHeadroom: frontHeadroom}
	}
	if darwinTUN, isDarwinTUN := tunInterface.(DarwinTUN); isDarwinTUN {
		return &systemWritebackDarwin{darwinTUN: darwinTUN, frontHeadroom: frontHeadroom}
	}
	return &systemWriteback{tun: tunInterface, frontHeadroom: frontHeadroom}
}

type systemWritebackLinux struct {
	linuxTUN      LinuxTUN
	frontHeadroom int
}

func (w *systemWritebackLinux) ReturnHeadroom() int {
	return w.frontHeadroom + PacketOffset
}

func (w *systemWritebackLinux) WriteReturnPackets(packets [][]byte) error {
	return common.Error(w.linuxTUN.BatchWrite(packets, w.frontHeadroom))
}

type systemWritebackDarwin struct {
	darwinTUN     DarwinTUN
	frontHeadroom int
}

func (w *systemWritebackDarwin) ReturnHeadroom() int {
	return w.frontHeadroom + PacketOffset
}

func (w *systemWritebackDarwin) WriteReturnPackets(packets [][]byte) error {
	buffers := make([]*buf.Buffer, 0, len(packets))
	for _, packet := range packets {
		buffers = append(buffers, buf.As(packet[PacketOffset:]))
	}
	return w.darwinTUN.BatchWrite(buffers)
}

type systemWriteback struct {
	tun           Tun
	frontHeadroom int
}

func (w *systemWriteback) ReturnHeadroom() int {
	return w.frontHeadroom + PacketOffset
}

func (w *systemWriteback) WriteReturnPackets(packets [][]byte) error {
	var writeErrors []error
	for _, packet := range packets {
		if PacketOffset > 0 {
			PacketFillHeader(packet, header.IPVersion(packet[PacketOffset:]))
		}
		_, err := w.tun.Write(packet)
		if err != nil {
			writeErrors = append(writeErrors, err)
		}
	}
	return E.Errors(writeErrors...)
}

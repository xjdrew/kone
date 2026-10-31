package tun

import (
	"maps"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	tcpEstablishedTimeout = 2*time.Hour + 4*time.Minute
	tcpTransitoryTimeout  = 4 * time.Minute
	tcpClosingTimeout     = 10 * time.Second

	defaultUDPTimeout = 5 * time.Minute

	defaultICMPTimeout = time.Minute

	flowTombstoneTimeout = 4 * time.Minute

	flowTableCapacity = 16384

	flowSweepInterval = 30 * time.Second
	flowSweepLimit    = flowTableCapacity / int(flowTombstoneTimeout/flowSweepInterval)
)

type ForwardWriteback interface {
	ReturnHeadroom() int
	WriteReturnPackets(packets [][]byte) error
}

type flowEntry struct {
	action   FlowAction
	deadline int64
	idle     time.Duration
	flow     *forwardFlow
}

type forwardFlow struct {
	nat          *portNAT
	reverseKey   flowKey
	forwardRule  rewriteRule
	reverseRule  rewriteRule
	effectiveMTU uint32
	protocol     uint8
	udpTimeout   time.Duration
	tracker      FlowTracker

	clientAddress            netip.Addr
	clientSelector           uint16
	clientDestinationAddress netip.Addr
	clientDestinationPort    uint16
	serverAddress            netip.Addr
	dnatAddress              bool
	dnatPort                 bool

	finForward  atomic.Bool
	established atomic.Bool
	finReverse  atomic.Bool
	reported    atomic.Bool
	closed      atomic.Bool
	aborted     atomic.Bool
	lastReverse atomic.Int64
}

func (f *forwardFlow) report(reason FlowCloseReason) {
	if !f.reported.CompareAndSwap(false, true) {
		return
	}
	if f.tracker != nil {
		f.tracker.CloseFlow(reason)
	}
}

func (f *forwardFlow) close(reason FlowCloseReason) {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	f.report(reason)
}

func (f *forwardFlow) CloseFlow() {
	f.aborted.Store(true)
	f.close(FlowCloseReset)
}

func (f *forwardFlow) observeReverse(packet *forwardPacket, now int64) {
	f.lastReverse.Store(now)
	if packet.protocol != uint8(header.TCPProtocolNumber) {
		return
	}
	if f.established.CompareAndSwap(false, true) && f.tracker != nil {
		f.tracker.FlowEstablished()
	}
	if packet.tcpFlags&header.TCPFlagRst != 0 {
		f.close(FlowCloseReset)
		return
	}
	if packet.tcpFlags&header.TCPFlagFin != 0 {
		f.finReverse.Store(true)
	} else if f.finReverse.Load() && f.finForward.Load() {
		f.report(FlowCloseFinished)
	}
}

type ForwardDispatcher struct {
	epoch       time.Time
	handler     Handler
	writeback   ForwardWriteback
	logger      logger.Logger
	udpTimeout  time.Duration
	icmpTimeout time.Duration
	access      sync.RWMutex

	table        map[flowKey]*flowEntry
	lastSweep    int64
	resetPending atomic.Bool
	ports        map[Port]*portNAT
	natList      atomic.Pointer[[]*portNAT]
	revNAT       atomic.Pointer[map[netip.Addr]*portNAT]

	activeNATs     []*portNAT
	writebackBatch [][]byte
	returnPath     forwardReturn
	exhaustedLogAt int64

	segmentBuffers [][]byte
	segmentSizes   []int
	segmentUsed    int
}

func addrToTCPIP(addr netip.Addr) tcpip.Address {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

func NewForwardDispatcher(handler Handler, writeback ForwardWriteback, logger logger.Logger, udpTimeout time.Duration, icmpTimeout time.Duration) *ForwardDispatcher {
	dispatcher := &ForwardDispatcher{
		epoch:       time.Now(),
		handler:     handler,
		writeback:   writeback,
		logger:      logger,
		udpTimeout:  udpTimeout,
		icmpTimeout: icmpTimeout,
		table:       make(map[flowKey]*flowEntry),
		ports:       make(map[Port]*portNAT),
	}
	if dispatcher.udpTimeout <= 0 {
		dispatcher.udpTimeout = defaultUDPTimeout
	}
	if dispatcher.icmpTimeout <= 0 {
		dispatcher.icmpTimeout = defaultICMPTimeout
	}
	dispatcher.returnPath.dispatcher = dispatcher
	return dispatcher
}

func (d *ForwardDispatcher) now() int64 {
	return int64(time.Since(d.epoch))
}

func (d *ForwardDispatcher) Close() {
	if d == nil {
		return
	}
	d.returnPath.closed.Store(true)
	d.access.Lock()
	flows := make([]*forwardFlow, 0, len(d.table))
	for _, entry := range d.table {
		if entry.flow != nil {
			flows = append(flows, entry.flow)
		}
	}
	ports := make([]Port, 0, len(d.ports))
	for port, nat := range d.ports {
		if nat != nil {
			ports = append(ports, port)
		}
	}
	d.access.Unlock()
	for _, flow := range flows {
		flow.close(FlowCloseReset)
	}
	for _, port := range ports {
		port.DetachReturn(&d.returnPath)
	}
}

func (d *ForwardDispatcher) Dispatch(packet []byte) bool {
	if d == nil || d.returnPath.closed.Load() {
		return false
	}
	parsed, ok := parseForwardPacket(packet)
	if !ok || parsed.fragment || !parsed.hasFlow {
		return false
	}
	d.access.RLock()
	if d.returnPath.closed.Load() {
		d.access.RUnlock()
		return false
	}
	key := parsed.flowKey()
	now := d.now()
	entry, loaded := d.table[key]
	if loaded && d.entryExpired(entry, now) {
		d.removeEntry(key, entry, FlowCloseTimeout)
		loaded = false
	}
	if loaded {
		handled := d.handleHit(key, entry, &parsed, packet, now)
		d.access.RUnlock()
		return handled
	}
	d.access.RUnlock()
	if parsed.protocol == uint8(header.TCPProtocolNumber) &&
		(parsed.tcpFlags&header.TCPFlagSyn == 0 || parsed.tcpFlags&header.TCPFlagAck != 0) {
		return false
	}
	return d.judgeAndInstall(key, &parsed, packet)
}

func (d *ForwardDispatcher) handleHit(key flowKey, entry *flowEntry, packet *forwardPacket, raw []byte, now int64) bool {
	switch entry.action {
	case ActionFlow:
		flow := entry.flow
		if flow.closed.Load() {
			d.tombstoneEntry(entry, now)
			return true
		}
		var flowFinished bool
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if packet.tcpFlags&header.TCPFlagRst != 0 {
				d.forwardToPort(flow, packet, raw)
				flow.close(FlowCloseReset)
				d.tombstoneEntry(entry, now)
				return true
			}
			if packet.tcpFlags&header.TCPFlagFin != 0 {
				flow.finForward.Store(true)
			} else if flow.finForward.Load() && flow.finReverse.Load() {
				flowFinished = true
			}
		}
		entry.idle = d.flowIdle(flow)
		entry.deadline = now + int64(entry.idle)
		d.forwardToPort(flow, packet, raw)
		if flowFinished {
			flow.report(FlowCloseFinished)
		}
		return true
	case ActionAccept:
		if packet.protocol == uint8(header.TCPProtocolNumber) && packet.tcpFlags&header.TCPFlagSyn == 0 {
			d.removeEntry(key, entry, FlowCloseReset)
			return false
		}
		entry.deadline = now + int64(entry.idle)
		return false
	case ActionReject:
		entry.deadline = now + int64(entry.idle)
		d.stageReject(packet)
		return true
	default:
		entry.deadline = now + int64(entry.idle)
		return true
	}
}

func (d *ForwardDispatcher) judgeAndInstall(key flowKey, packet *forwardPacket, raw []byte) bool {
	var firstPacket []byte
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		firstPacket = header.UDP(packet.transport).Payload()
	}
	verdict := d.handler.JudgeFlow(packet.protocol, packet.source, packet.destination, firstPacket)
	if verdict.Action == ActionBypass && verdict.Port != nil {
		verdict.Action = ActionFlow
	}
	d.access.RLock()
	defer d.access.RUnlock()
	if d.returnPath.closed.Load() {
		return false
	}
	now := d.now()
	switch verdict.Action {
	case ActionFlow:
		if verdict.Port != nil {
			flow, result := d.createFlow(packet, verdict)
			if result == createFlowOK {
				entry := &flowEntry{action: ActionFlow, flow: flow, idle: d.flowIdle(flow)}
				entry.deadline = now + int64(entry.idle)
				d.insertEntry(key, entry, now)
				d.forwardToPort(flow, packet, raw)
				return true
			}
			if result == createFlowExhausted {
				if now-d.exhaustedLogAt >= int64(exhaustedLogInterval) {
					d.exhaustedLogAt = now
					d.logger.Warn("port selector range exhausted, rejecting flow to ", packet.destination)
				}
				d.installSimple(key, ActionReject, packet.protocol, now)
				d.stageReject(packet)
				return true
			}
		}
		d.installSimple(key, ActionAccept, packet.protocol, now)
		return false
	case ActionReject:
		d.installSimple(key, ActionReject, packet.protocol, now)
		d.stageReject(packet)
		return true
	case ActionDrop:
		d.installSimple(key, ActionDrop, packet.protocol, now)
		return true
	case ActionHijackDNS:
		if packet.protocol == uint8(header.UDPProtocolNumber) {
			d.hijackDNSPacket(packet)
			return true
		}
		d.installSimple(key, ActionAccept, packet.protocol, now)
		return false
	default:
		d.installSimple(key, ActionAccept, packet.protocol, now)
		return false
	}
}

func (d *ForwardDispatcher) installSimple(key flowKey, action FlowAction, protocol uint8, now int64) {
	entry := &flowEntry{action: action, idle: d.idleTimeout(protocol, false)}
	entry.deadline = now + int64(entry.idle)
	d.insertEntry(key, entry, now)
}

func (d *ForwardDispatcher) idleTimeout(protocol uint8, established bool) time.Duration {
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		if established {
			return tcpEstablishedTimeout
		}
		return tcpTransitoryTimeout
	case uint8(header.UDPProtocolNumber):
		return d.udpTimeout
	default:
		return d.icmpTimeout
	}
}

func (d *ForwardDispatcher) flowIdle(flow *forwardFlow) time.Duration {
	if flow.protocol == uint8(header.TCPProtocolNumber) && flow.finForward.Load() && flow.finReverse.Load() {
		return tcpClosingTimeout
	}
	if flow.udpTimeout > 0 {
		return flow.udpTimeout
	}
	established := flow.established.Load() && !flow.finForward.Load() && !flow.finReverse.Load()
	return d.idleTimeout(flow.protocol, established)
}

type createFlowResult uint8

const (
	createFlowOK createFlowResult = iota
	createFlowUnsupported
	createFlowExhausted
)

const exhaustedLogInterval = 5 * time.Second

func (d *ForwardDispatcher) createFlow(packet *forwardPacket, verdict FlowVerdict) (*forwardFlow, createFlowResult) {
	var portAddress netip.Addr
	inet4Address, inet6Address := verdict.Port.PortAddresses()
	if packet.ipVersion == 6 {
		portAddress = inet6Address
	} else {
		portAddress = inet4Address
	}
	if !portAddress.IsValid() {
		return nil, createFlowUnsupported
	}
	effectiveMTU := verdict.Port.PortMTU()
	if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
		return nil, createFlowUnsupported
	}
	isICMP := isICMPProtocol(packet.protocol)
	clientDestinationAddress := packet.destination.Addr()
	clientDestinationPort := packet.destination.Port()
	serverAddress := clientDestinationAddress
	serverPort := clientDestinationPort
	if verdict.Destination.Addr().IsValid() {
		serverAddress = verdict.Destination.Addr()
		if serverAddress.Is4() != clientDestinationAddress.Is4() {
			return nil, createFlowUnsupported
		}
	}
	if verdict.Destination.Port() != 0 && !isICMP {
		serverPort = verdict.Destination.Port()
	}
	nat := d.natFor(verdict.Port)
	if nat == nil {
		return nil, createFlowUnsupported
	}
	selector, reverseKey, allocated := nat.allocateSelector(packet.protocol, portAddress, serverAddress, serverPort, packet.source.Port())
	if !allocated {
		return nil, createFlowExhausted
	}
	var udpTimeout time.Duration
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		udpTimeout = verdict.UDPTimeout
	}
	flow := &forwardFlow{
		nat:                      nat,
		reverseKey:               reverseKey,
		effectiveMTU:             effectiveMTU,
		protocol:                 packet.protocol,
		udpTimeout:               udpTimeout,
		clientAddress:            packet.source.Addr(),
		clientSelector:           packet.source.Port(),
		clientDestinationAddress: clientDestinationAddress,
		clientDestinationPort:    clientDestinationPort,
		serverAddress:            serverAddress,
		dnatAddress:              serverAddress != clientDestinationAddress,
		dnatPort:                 serverPort != clientDestinationPort && !isICMP,
	}
	flow.forwardRule = rewriteRule{
		sourceAddress:     addrToTCPIP(portAddress),
		sourcePort:        selector,
		rewriteSourcePort: true,
	}
	if flow.dnatAddress {
		flow.forwardRule.destinationAddress = addrToTCPIP(serverAddress)
	}
	if flow.dnatPort {
		flow.forwardRule.destinationPort = serverPort
		flow.forwardRule.rewriteDestinationPort = true
	}
	flow.reverseRule = rewriteRule{
		destinationAddress:     addrToTCPIP(flow.clientAddress),
		destinationPort:        flow.clientSelector,
		rewriteDestinationPort: true,
	}
	if flow.dnatAddress {
		flow.reverseRule.sourceAddress = addrToTCPIP(clientDestinationAddress)
	}
	if flow.dnatPort {
		flow.reverseRule.sourcePort = clientDestinationPort
		flow.reverseRule.rewriteSourcePort = true
	}
	if verdict.NewTracker != nil {
		flow.tracker = verdict.NewTracker()
		if flow.tracker != nil {
			flow.tracker.AttachFlow(flow)
		}
	}
	nat.insert(reverseKey, flow)
	return flow, createFlowOK
}

func (d *ForwardDispatcher) natFor(port Port) *portNAT {
	nat, loaded := d.ports[port]
	if loaded {
		return nat
	}
	err := port.AttachReturn(&d.returnPath)
	if err != nil {
		d.logger.Trace(E.Cause(err, "attach return path"))
		return nil
	}
	nat = newPortNAT(port)
	d.ports[port] = nat
	var natList []*portNAT
	current := d.natList.Load()
	if current != nil {
		natList = append(natList, *current...)
	}
	natList = append(natList, nat)
	d.natList.Store(&natList)
	revMap := make(map[netip.Addr]*portNAT)
	if currentRev := d.revNAT.Load(); currentRev != nil {
		maps.Copy(revMap, *currentRev)
	}
	v4Address, v6Address := port.PortAddresses()
	if v4Address.IsValid() {
		revMap[v4Address] = nat
	}
	if v6Address.IsValid() {
		revMap[v6Address] = nat
	}
	d.revNAT.Store(&revMap)
	return nat
}

func (d *ForwardDispatcher) forwardToPort(flow *forwardFlow, packet *forwardPacket, raw []byte) {
	if flow.effectiveMTU != 0 && uint32(len(raw)) > flow.effectiveMTU {
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if flow.tracker != nil {
				flow.tracker.CountForward(len(raw))
			}
			d.rewriteForward(flow, packet)
			d.resegmentTCP(flow, packet, raw)
			return
		}
		if packet.ipVersion == 4 {
			ipHdr := packet.network.(header.IPv4)
			if ipHdr.Flags()&header.IPv4FlagDontFragment == 0 {
				if flow.tracker != nil {
					flow.tracker.CountForward(len(raw))
				}
				d.rewriteForward(flow, packet)
				fragments, ok := fragmentIPv4Packet(ipHdr, flow.effectiveMTU)
				if ok {
					for _, fragment := range fragments {
						d.stagePort(flow.nat, fragment)
					}
				}
				return
			}
			reply, ok := buildFragmentationNeeded(ipHdr, flow.effectiveMTU, d.writeback.ReturnHeadroom())
			if ok {
				d.writebackBatch = append(d.writebackBatch, reply)
			}
			return
		}
		reply, ok := buildPacketTooBig(packet.network.(header.IPv6), flow.effectiveMTU, d.writeback.ReturnHeadroom())
		if ok {
			d.writebackBatch = append(d.writebackBatch, reply)
		}
		return
	}
	if flow.tracker != nil {
		flow.tracker.CountForward(len(raw))
	}
	d.rewriteForward(flow, packet)
	d.stagePort(flow.nat, raw)
}

func (d *ForwardDispatcher) rewriteForward(flow *forwardFlow, packet *forwardPacket) {
	if packet.isTCPSyn() {
		applyRewriteRaw(packet, &flow.forwardRule)
		clampTCPMSS(packet, flow.effectiveMTU)
		recomputeChecksums(packet)
	} else {
		applyRewrite(packet, &flow.forwardRule)
	}
}

func (d *ForwardDispatcher) stagePort(nat *portNAT, packet []byte) {
	if len(nat.pending) == 0 {
		d.activeNATs = append(d.activeNATs, nat)
	}
	nat.pending = append(nat.pending, packet)
}

func (d *ForwardDispatcher) flushPort(nat *portNAT) {
	if len(nat.pending) == 0 {
		return
	}
	err := nat.port.WritePackets(nat.pending)
	if err != nil {
		d.logger.Trace(E.Cause(err, "forward packets"))
	}
	nat.pending = nat.pending[:0]
}

func (d *ForwardDispatcher) stageReject(packet *forwardPacket) {
	reply, ok := buildReject(packet, d.writeback.ReturnHeadroom())
	if ok {
		d.writebackBatch = append(d.writebackBatch, reply)
	}
}

func (d *ForwardDispatcher) ResetNetwork() {
	if d == nil {
		return
	}
	d.resetPending.Store(true)
}

func (d *ForwardDispatcher) Flush() {
	if d == nil || d.returnPath.closed.Load() {
		return
	}
	d.access.RLock()
	defer d.access.RUnlock()
	if d.returnPath.closed.Load() {
		return
	}
	if d.resetPending.Swap(false) {
		for key, entry := range d.table {
			d.removeEntry(key, entry, FlowCloseReset)
		}
	}
	for _, nat := range d.activeNATs {
		d.flushPort(nat)
	}
	d.activeNATs = d.activeNATs[:0]
	if retain := max(d.segmentUsed, segmentRetainCount); len(d.segmentBuffers) > retain {
		clear(d.segmentBuffers[retain:])
		d.segmentBuffers = d.segmentBuffers[:retain]
		d.segmentSizes = d.segmentSizes[:retain]
	}
	d.segmentUsed = 0
	if len(d.writebackBatch) > 0 {
		err := d.writeback.WriteReturnPackets(d.writebackBatch)
		if err != nil {
			d.logger.Trace(E.Cause(err, "write back packets"))
		}
		d.writebackBatch = d.writebackBatch[:0]
	}
	d.maybeSweep(d.now())
}

func (d *ForwardDispatcher) entryExpired(entry *flowEntry, now int64) bool {
	if entry.flow != nil && entry.flow.aborted.Load() {
		return true
	}
	if now <= entry.deadline {
		return false
	}
	if entry.action == ActionFlow {
		lastReverse := entry.flow.lastReverse.Load()
		reverseDeadline := lastReverse + int64(entry.idle)
		if lastReverse != 0 && now <= reverseDeadline {
			entry.deadline = reverseDeadline
			return false
		}
	}
	return true
}

func (d *ForwardDispatcher) tombstoneEntry(entry *flowEntry, now int64) {
	entry.action = ActionDrop
	entry.idle = flowTombstoneTimeout
	entry.deadline = now + int64(entry.idle)
}

func (d *ForwardDispatcher) removeEntry(key flowKey, entry *flowEntry, reason FlowCloseReason) {
	delete(d.table, key)
	if entry.flow != nil {
		if reason == FlowCloseTimeout && entry.flow.finForward.Load() && entry.flow.finReverse.Load() {
			reason = FlowCloseFinished
		}
		entry.flow.close(reason)
		entry.flow.nat.delete(entry.flow.reverseKey)
	}
}

func (d *ForwardDispatcher) insertEntry(key flowKey, entry *flowEntry, now int64) {
	if len(d.table) >= flowTableCapacity {
		d.evictEntries(now)
	}
	d.table[key] = entry
}

func (d *ForwardDispatcher) evictEntries(now int64) {
	var (
		freed     int
		visited   int
		oldestKey flowKey
		oldest    *flowEntry
	)
	for key, entry := range d.table {
		if d.entryExpired(entry, now) {
			d.removeEntry(key, entry, FlowCloseTimeout)
			freed++
		} else if oldest == nil || entry.deadline < oldest.deadline {
			oldestKey = key
			oldest = entry
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
	if freed == 0 && oldest != nil {
		d.removeEntry(oldestKey, oldest, FlowCloseReset)
	}
}

func (d *ForwardDispatcher) maybeSweep(now int64) {
	if now-d.lastSweep < int64(flowSweepInterval) {
		return
	}
	d.lastSweep = now
	visited := 0
	for key, entry := range d.table {
		if d.entryExpired(entry, now) {
			d.removeEntry(key, entry, FlowCloseTimeout)
		} else if entry.action == ActionFlow && entry.flow.closed.Load() {
			d.tombstoneEntry(entry, now)
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
}

func isICMPProtocol(protocol uint8) bool {
	return protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber)
}

var _ Return = (*forwardReturn)(nil)

type forwardReturn struct {
	dispatcher *ForwardDispatcher
	closed     atomic.Bool
}

func (r *forwardReturn) ReturnHeadroom() int {
	return r.dispatcher.writeback.ReturnHeadroom()
}

type returnDecision uint8

const (
	returnPass returnDecision = iota
	returnWrite
	returnDrop
)

func (r *forwardReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.closed.Load() {
		return packets
	}
	natListPtr := r.dispatcher.natList.Load()
	if natListPtr == nil {
		return packets
	}
	natList := *natListPtr
	var revMap map[netip.Addr]*portNAT
	if revPtr := r.dispatcher.revNAT.Load(); revPtr != nil {
		revMap = *revPtr
	}
	headroom := r.dispatcher.writeback.ReturnHeadroom()
	now := r.dispatcher.now()

	if len(packets) == 1 {
		switch r.classifyReturn(packets[0], natList, revMap, headroom, now) {
		case returnWrite:
			if err := r.dispatcher.writeback.WriteReturnPackets(packets[:1]); err != nil {
				r.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
			}
			return packets[:0]
		case returnDrop:
			return packets[:0]
		default:
			return packets
		}
	}

	unconsumed := packets[:0]
	var writeBatch [][]byte
	for _, raw := range packets {
		switch r.classifyReturn(raw, natList, revMap, headroom, now) {
		case returnWrite:
			writeBatch = append(writeBatch, raw)
		case returnDrop:
		default:
			unconsumed = append(unconsumed, raw)
		}
	}
	if len(writeBatch) > 0 {
		if err := r.dispatcher.writeback.WriteReturnPackets(writeBatch); err != nil {
			r.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
		}
	}
	return unconsumed
}

func (r *forwardReturn) classifyReturn(raw []byte, natList []*portNAT, revMap map[netip.Addr]*portNAT, headroom int, now int64) returnDecision {
	if len(raw) < headroom+header.IPv4MinimumSize {
		return returnPass
	}
	parsed, ok := parseForwardPacket(raw[headroom:])
	if !ok || parsed.fragment {
		return returnPass
	}
	if !parsed.hasFlow {
		if parsed.isICMPError() && returnICMPError(natList, revMap, &parsed) {
			return returnWrite
		}
		return returnPass
	}
	flow := findReverseFlow(natList, revMap, parsed.flowKey())
	if flow == nil {
		return returnPass
	}
	if flow.closed.Load() {
		return returnDrop
	}
	if flow.tracker != nil {
		flow.tracker.CountReverse(len(raw) - headroom)
	}
	flow.observeReverse(&parsed, now)
	if parsed.isTCPSyn() {
		applyRewriteRaw(&parsed, &flow.reverseRule)
		clampTCPMSS(&parsed, flow.effectiveMTU)
		recomputeChecksums(&parsed)
	} else {
		applyRewrite(&parsed, &flow.reverseRule)
	}
	return returnWrite
}

func findReverseFlow(natList []*portNAT, revMap map[netip.Addr]*portNAT, key flowKey) *forwardFlow {
	if nat, ok := revMap[key.destination.Addr()]; ok {
		if flow := nat.lookup(key); flow != nil {
			return flow
		}
	}
	for _, nat := range natList {
		if flow := nat.lookup(key); flow != nil {
			return flow
		}
	}
	return nil
}

func returnICMPError(natList []*portNAT, revMap map[netip.Addr]*portNAT, parsed *forwardPacket) bool {
	inner, ok := parsed.icmpErrorInner()
	if !ok {
		return false
	}
	embedded, parsedInner := parseEmbedded(inner)
	if !parsedInner {
		return false
	}
	flow := findReverseFlow(natList, revMap, embedded.flowKey().reversed())
	if flow == nil || flow.closed.Load() {
		return false
	}
	rewriteEmbeddedSource(&embedded, addrToTCPIP(flow.clientAddress), flow.clientSelector, true)
	if flow.dnatAddress || flow.dnatPort {
		rewriteEmbeddedDestination(&embedded, addrToTCPIP(flow.clientDestinationAddress), flow.clientDestinationPort, flow.dnatPort)
	}
	parsed.network.SetDestinationAddr(flow.clientAddress)
	if parsed.network.SourceAddr() == flow.serverAddress {
		parsed.network.SetSourceAddr(flow.clientDestinationAddress)
	}
	recomputeChecksums(parsed)
	return true
}

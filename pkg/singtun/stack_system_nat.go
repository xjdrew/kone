package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type TCPNat struct {
	timeout    time.Duration
	portIndex  uint16
	portAccess sync.RWMutex
	addrAccess sync.RWMutex
	addrMap    map[tcpNatKey]uint16
	portMap    map[uint16]*TCPSession
}

type tcpNatKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type TCPSession struct {
	sync.Mutex
	Source      netip.AddrPort
	Destination netip.AddrPort
	LastActive  time.Time
	finForward  bool
	finReverse  bool
	closed      bool
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	natMap := &TCPNat{
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[tcpNatKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
	go natMap.loopCheckTimeout(ctx)
	return natMap
}

func (n *TCPNat) loopCheckTimeout(ctx context.Context) {
	ticker := time.NewTicker(min(n.timeout, flowSweepInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-ctx.Done():
			return
		}
	}
}

func (n *TCPNat) checkTimeout() {
	now := time.Now()
	type expiredSession struct {
		port    uint16
		session *TCPSession
	}
	var expired []expiredSession
	n.portAccess.RLock()
	for natPort, session := range n.portMap {
		session.Lock()
		timedOut := n.expiredLocked(session, now)
		session.Unlock()
		if timedOut {
			expired = append(expired, expiredSession{port: natPort, session: session})
		}
	}
	n.portAccess.RUnlock()
	if len(expired) == 0 {
		return
	}
	n.addrAccess.Lock()
	n.portAccess.Lock()
	for _, e := range expired {
		e.session.Lock()
		if n.portMap[e.port] == e.session && n.expiredLocked(e.session, now) {
			delete(n.addrMap, tcpNatKey{Source: e.session.Source, Destination: e.session.Destination})
			delete(n.portMap, e.port)
		}
		e.session.Unlock()
	}
	n.portAccess.Unlock()
	n.addrAccess.Unlock()
}

func (n *TCPNat) expiredLocked(session *TCPSession, now time.Time) bool {
	if session.closed {
		return now.Sub(session.LastActive) > tcpClosingTimeout
	}
	return now.Sub(session.LastActive) > n.timeout
}

func (n *TCPNat) LookupBack(port uint16, flags header.TCPFlags) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.observe(flags, true)
	}
	return session
}

func (s *TCPSession) observe(flags header.TCPFlags, reverse bool) bool {
	s.Lock()
	defer s.Unlock()
	if s.closed && !reverse && flags&header.TCPFlagSyn != 0 && flags&header.TCPFlagAck == 0 {
		return false
	}
	if flags&header.TCPFlagRst != 0 {
		s.closed = true
	} else if flags&header.TCPFlagFin != 0 {
		if reverse {
			s.finReverse = true
		} else {
			s.finForward = true
		}
		s.closed = s.finForward && s.finReverse
	} else if time.Since(s.LastActive) <= time.Second {
		return true
	}
	s.LastActive = time.Now()
	return true
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort, flags header.TCPFlags) uint16 {
	key := tcpNatKey{Source: source, Destination: destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded && n.observe(port, flags) {
		return port
	}
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	port, loaded = n.addrMap[key]
	if loaded && n.observe(port, flags) {
		return port
	}
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	nextPort, ok := n.allocatePortLocked()
	if !ok {
		return 0
	}
	if loaded {
		delete(n.portMap, port)
	}
	n.portMap[nextPort] = &TCPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}
	n.addrMap[key] = nextPort
	return nextPort
}

func (n *TCPNat) observe(port uint16, flags header.TCPFlags) bool {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	return session != nil && session.observe(flags, false)
}

func (n *TCPNat) allocatePortLocked() (uint16, bool) {
	for range 65535 - 10000 + 1 {
		nextPort := n.portIndex
		if nextPort == 0 {
			nextPort = 10000
			n.portIndex = 10001
		} else {
			n.portIndex++
		}
		if _, occupied := n.portMap[nextPort]; !occupied {
			return nextPort, true
		}
	}
	return 0, false
}

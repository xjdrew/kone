package kone

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	NatSessionLifeSeconds   = 600
	NatSessionCheckInterval = 300
)

// TCP and UDP have separate tables; each flow is identified by both endpoints.
type flowKey struct{ src, dst netip.AddrPort }

type NatSession struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	lastTouch        int64
}

type Nat struct {
	mu        sync.Mutex
	from, to  uint16
	next      int
	ports     map[flowKey]uint16
	sessions  []*NatSession
	lastCheck int64
}

func sessionKey(srcIP, dstIP net.IP, srcPort, dstPort uint16) (flowKey, bool) {
	src, ok := netip.AddrFromSlice(srcIP)
	if !ok || !src.Unmap().Is4() {
		return flowKey{}, false
	}
	dst, ok := netip.AddrFromSlice(dstIP)
	if !ok || !dst.Unmap().Is4() {
		return flowKey{}, false
	}
	return flowKey{netip.AddrPortFrom(src.Unmap(), srcPort), netip.AddrPortFrom(dst.Unmap(), dstPort)}, true
}

// getSession returns a snapshot; no caller observes mutable table state.
func (nat *Nat) getSession(port uint16) *NatSession {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	if port < nat.from || port >= nat.to || int(port)-int(nat.from) >= len(nat.sessions) {
		return nil
	}
	session := nat.sessions[int(port)-int(nat.from)]
	if session == nil {
		return nil
	}
	session.lastTouch = time.Now().Unix()
	copy := *session
	copy.srcIP = append(net.IP(nil), session.srcIP...)
	copy.dstIP = append(net.IP(nil), session.dstIP...)
	return &copy
}

// allocSession returns port zero on exhaustion or invalid endpoints. Callers
// must drop the packet instead of writing an invalid translated source port.
func (nat *Nat) allocSession(srcIP, dstIP net.IP, srcPort, dstPort uint16) (bool, uint16) {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	key, ok := sessionKey(srcIP, dstIP, srcPort, dstPort)
	if !ok {
		return false, 0
	}
	now := time.Now().Unix()
	nat.clearExpiredLocked(now, len(nat.ports) == len(nat.sessions))
	if port, ok := nat.ports[key]; ok {
		nat.sessions[int(port)-int(nat.from)].lastTouch = now
		return false, port
	}
	for i := 0; i < len(nat.sessions); i++ {
		index := (nat.next + i) % len(nat.sessions)
		if nat.sessions[index] != nil {
			continue
		}
		port := uint16(int(nat.from) + index)
		nat.sessions[index] = &NatSession{srcIP: append(net.IP(nil), srcIP.To4()...), dstIP: append(net.IP(nil), dstIP.To4()...), srcPort: srcPort, dstPort: dstPort, lastTouch: now}
		nat.ports[key] = port
		nat.next = (index + 1) % len(nat.sessions)
		return true, port
	}
	return false, 0
}

func (nat *Nat) clearExpiredSessions(now int64) {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	nat.clearExpiredLocked(now, false)
}

func (nat *Nat) clearExpiredLocked(now int64, force bool) {
	if !force && now-nat.lastCheck < NatSessionCheckInterval {
		return
	}
	nat.lastCheck = now
	for index, s := range nat.sessions {
		if s != nil && now-s.lastTouch >= NatSessionLifeSeconds {
			key, _ := sessionKey(s.srcIP, s.dstIP, s.srcPort, s.dstPort)
			delete(nat.ports, key)
			nat.sessions[index] = nil
		}
	}
}

func (nat *Nat) count() int {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	return len(nat.ports)
}

// NewNat allocates an exclusive port range [from,to). Invalid ranges are empty.
func NewNat(from, to uint16) *Nat {
	count := 0
	if from > 0 && to > from {
		count = int(to) - int(from)
	}
	slog.Debug("NAT table created", "port_start", from, "port_end", to)
	return &Nat{from: from, to: to, ports: make(map[flowKey]uint16, count), sessions: make([]*NatSession, count)}
}

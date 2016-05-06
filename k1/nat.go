package k1

import (
	"net"
	"sync"
	"time"
)

const (
	NatSessionLifeSeconds   = 600
	NatSessionCheckInterval = 300
)

type NatTable struct {
	from uint16
	to   uint16

	next   uint16 // next avaliable port
	h2Port map[uint64]uint16
	mapped []bool

	lock sync.Mutex
}

func hashAddr(ip net.IP, port uint16) uint64 {
	v := uint64(ip[0]) << 40
	v += uint64(ip[1]) << 32
	v += uint64(ip[2]) << 24
	v += uint64(ip[3]) << 16
	v += uint64(port)
	return v
}

func (table *NatTable) Unmap(ip net.IP, port uint16) {
	h := hashAddr(ip, port)

	table.lock.Lock()
	defer table.lock.Unlock()
	if port, ok := table.h2Port[h]; ok {
		delete(table.h2Port, h)
		table.mapped[port-table.from] = false
	}
}

// return: mapped port, is new mapped
func (table *NatTable) Map(ip net.IP, port uint16) (uint16, bool) {
	h := hashAddr(ip, port)

	table.lock.Lock()
	defer table.lock.Unlock()
	if port, ok := table.h2Port[h]; ok {
		return port, false
	}

	from := table.from
	to := table.to
	next := table.next
	var i uint16
	for ; i < to-from; i++ {
		next = next + i
		if next >= to {
			next = next%to + from
		}

		if table.mapped[next-from] {
			continue
		}
		table.mapped[next-from] = true
		table.h2Port[h] = next
		table.next = next + 1
		return next, true
	}
	return 0, false
}

type NatSession struct {
	srcIP     net.IP
	dstIP     net.IP
	srcPort   uint16
	dstPort   uint16
	dstHost   string
	lastTouch int64
}

type Nat struct {
	table    *NatTable
	sessions map[uint16]*NatSession
	lock     sync.Mutex

	checkThreshold int
	lastCheck      int64
}

func (nat *Nat) getSession(port uint16) *NatSession {
	nat.lock.Lock()
	session := nat.sessions[port]
	if session != nil {
		session.lastTouch = time.Now().Unix()
	}

	nat.lock.Unlock()
	return session
}

func (nat *Nat) releaseSessionLocked(port uint16) {
	session := nat.sessions[port]
	if session != nil {
		delete(nat.sessions, port)
		nat.table.Unmap(session.srcIP, session.srcPort)
	}
}

func (nat *Nat) releaseSession(port uint16) {
	nat.lock.Lock()
	nat.releaseSessionLocked(port)
	nat.lock.Unlock()
}

func (nat *Nat) allocSession(srcIP, dstIP net.IP, srcPort, dstPort uint16) uint16 {
	port, isNew := nat.table.Map(srcIP, srcPort)
	if isNew {
		session := &NatSession{
			srcIP:     srcIP,
			dstIP:     dstIP,
			srcPort:   srcPort,
			dstPort:   dstPort,
			dstHost:   dstIP.String(),
			lastTouch: time.Now().Unix(),
		}
		nat.lock.Lock()
		nat.sessions[port] = session
		nat.lock.Unlock()
	}
	return port
}

func (nat *Nat) clearExpiredSession() {
	now := time.Now().Unix()
	if now-nat.lastCheck < NatSessionCheckInterval {
		return
	}

	nat.lock.Lock()
	defer nat.lock.Unlock()
	if len(nat.sessions) < nat.checkThreshold {
		return
	}

	for port, session := range nat.sessions {
		if now-session.lastTouch > NatSessionLifeSeconds {
			nat.releaseSessionLocked(port)
		}
	}
}

func (nat *Nat) count() int {
	nat.lock.Lock()
	defer nat.lock.Unlock()
	return len(nat.sessions)
}

func newNat(from, to uint16) *Nat {
	count := to - from
	table := &NatTable{
		from:   from,
		to:     to,
		next:   from,
		h2Port: make(map[uint64]uint16, count),
		mapped: make([]bool, count),
	}

	logger.Infof("nat port range [%d, %d)", from, to)

	return &Nat{
		table:          table,
		sessions:       make(map[uint16]*NatSession, count),
		checkThreshold: int(count) / 10,
	}
}

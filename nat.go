//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"net"
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
}

func hashAddr(ip net.IP, port uint16) uint64 {
	v := uint64(ip[0]) << 40
	v += uint64(ip[1]) << 32
	v += uint64(ip[2]) << 24
	v += uint64(ip[3]) << 16
	v += uint64(port)
	return v
}

func (tbl *NatTable) Unmap(ip net.IP, port uint16) {
	h := hashAddr(ip, port)
	if port, ok := tbl.h2Port[h]; ok {
		delete(tbl.h2Port, h)
		tbl.mapped[port-tbl.from] = false
	}
}

// return: mapped port, is new mapped
func (tbl *NatTable) Map(ip net.IP, port uint16) (uint16, bool) {
	h := hashAddr(ip, port)
	if port, ok := tbl.h2Port[h]; ok {
		return port, false
	}

	from := tbl.from
	to := tbl.to
	next := tbl.next
	var i uint16
	for ; i < to-from; i++ {
		next = next + i
		if next >= to {
			next = next%to + from
		}

		if tbl.mapped[next-from] {
			continue
		}
		tbl.mapped[next-from] = true
		tbl.h2Port[h] = next
		tbl.next = next + 1
		return next, true
	}
	return 0, false
}

func (tbl *NatTable) Count() int {
	return len(tbl.h2Port)
}

type NatSession struct {
	srcIP     net.IP
	dstIP     net.IP
	srcPort   uint16
	dstPort   uint16
	lastTouch int64
}

type Nat struct {
	tbl      *NatTable
	sessions []*NatSession

	checkThreshold int
	lastCheck      int64
}

func (nat *Nat) getSession(port uint16) *NatSession {
	if port < nat.tbl.from || port >= nat.tbl.to {
		return nil
	}

	session := nat.sessions[port-nat.tbl.from]
	if session != nil {
		session.lastTouch = time.Now().Unix()
	}

	return session
}

func (nat *Nat) allocSession(srcIP, dstIP net.IP, srcPort, dstPort uint16) (bool, uint16) {
	now := time.Now().Unix()
	nat.clearExpiredSessions(now)

	tbl := nat.tbl
	port, isNew := tbl.Map(srcIP, srcPort)
	if isNew {
		session := &NatSession{
			srcIP:     srcIP,
			dstIP:     dstIP,
			srcPort:   srcPort,
			dstPort:   dstPort,
			lastTouch: now,
		}
		nat.sessions[port-tbl.from] = session
	}
	return isNew, port
}

func (nat *Nat) clearExpiredSessions(now int64) {
	if now-nat.lastCheck < NatSessionCheckInterval {
		return
	}

	if nat.count() < nat.checkThreshold {
		return
	}

	nat.lastCheck = now
	for index, session := range nat.sessions {
		if session != nil && now-session.lastTouch >= NatSessionLifeSeconds {
			nat.sessions[index] = nil
			nat.tbl.Unmap(session.srcIP, session.srcPort)
		}
	}
}

func (nat *Nat) count() int {
	return nat.tbl.Count()
}

// port range [from, to)
func NewNat(from, to uint16) *Nat {
	count := to - from
	tbl := &NatTable{
		from:   from,
		to:     to,
		next:   from,
		h2Port: make(map[uint64]uint16, count),
		mapped: make([]bool, count),
	}

	logger.Infof("nat port range [%d, %d)", from, to)

	return &Nat{
		tbl:            tbl,
		sessions:       make([]*NatSession, count),
		checkThreshold: int(count) / 10,
	}
}

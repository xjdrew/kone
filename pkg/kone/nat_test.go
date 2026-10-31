//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"github.com/stretchr/testify/require"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNatAlloc(t *testing.T) {
	var from uint16 = 10
	var to uint16 = 20
	nat := NewNat(from, to)

	srcIP := net.ParseIP("127.0.0.1")
	dstIP := srcIP

	// map all ports
	for i := from; i < to; i++ {
		_, port := nat.allocSession(srcIP, dstIP, i, i)
		if i != port {
			t.Error("alloc session failed")
			return
		}
	}

	// release all sessions
	now := time.Now().Unix() + NatSessionLifeSeconds
	nat.clearExpiredSessions(now)
	if nat.count() != 0 {
		t.Error("release session failed")
		return
	}

	// test get session
	srcPort := uint16(rand.Int())
	dstPort := uint16(rand.Int())
	_, port := nat.allocSession(srcIP, dstIP, srcPort, dstPort)
	session := nat.getSession(port)
	if session == nil {
		t.Error("get session failed")
		return
	}

	if !net.IP.Equal(session.srcIP, srcIP) || !net.IP.Equal(session.dstIP, dstIP) ||
		session.srcPort != srcPort || session.dstPort != dstPort {
		t.Error("check session failed")
		return
	}
}

func TestNatFlowIdentity(t *testing.T) {
	nat := NewNat(10000, 10010)
	src := net.ParseIP("192.168.1.2")
	_, a := nat.allocSession(src, net.ParseIP("1.1.1.1"), 50000, 443)
	_, b := nat.allocSession(src, net.ParseIP("8.8.8.8"), 50000, 443)
	_, c := nat.allocSession(src, net.ParseIP("1.1.1.1"), 50000, 53)
	_, d := nat.allocSession(net.ParseIP("192.168.1.3"), net.ParseIP("1.1.1.1"), 50000, 443)
	require.Len(t, map[uint16]bool{a: true, b: true, c: true, d: true}, 4)
	newFlow, same := nat.allocSession(src.To4(), net.ParseIP("1.1.1.1").To4(), 50000, 443)
	require.False(t, newFlow)
	require.Equal(t, a, same)
	require.Equal(t, uint16(53), nat.getSession(c).dstPort)
	require.True(t, net.ParseIP("8.8.8.8").Equal(nat.getSession(b).dstIP))
}

func TestNatExhaustionAndReuse(t *testing.T) {
	nat := NewNat(65530, 65535)
	for port := uint16(1); port <= 5; port++ {
		fresh, mapped := nat.allocSession(net.IPv4(192, 168, 1, 2), net.IPv4(1, 1, 1, 1), port, 443)
		require.True(t, fresh)
		require.GreaterOrEqual(t, mapped, uint16(65530))
		require.Less(t, mapped, uint16(65535))
	}
	_, port := nat.allocSession(net.IPv4(192, 168, 1, 2), net.IPv4(1, 1, 1, 1), 6, 443)
	require.Zero(t, port)
	nat.clearExpiredSessions(time.Now().Unix() + NatSessionLifeSeconds + 1)
	require.Zero(t, nat.count())
	fresh, port := nat.allocSession(net.IPv4(192, 168, 1, 2), net.IPv4(1, 1, 1, 1), 6, 443)
	require.True(t, fresh)
	require.NotZero(t, port)
	_, port = NewNat(20, 10).allocSession(nil, nil, 0, 0)
	require.Zero(t, port)
}

func TestNatConcurrentAccessAndSnapshots(t *testing.T) {
	nat := NewNat(10000, 10200)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, port := nat.allocSession(net.IPv4(192, 168, 1, byte(i+1)), net.IPv4(1, 1, 1, 1), uint16(i+1), 443)
				s := nat.getSession(port)
				if s == nil {
					t.Error("session missing")
					return
				}
				s.srcIP[0] = 0 // modifying a snapshot must not mutate a table entry
				if nat.getSession(port).srcIP[0] != 192 {
					t.Error("snapshot aliases table")
					return
				}
				nat.count()
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, 16, nat.count())
}

func BenchmarkNat(b *testing.B) {
	var from uint16 = 10000
	var to uint16 = 60000
	nat := NewNat(from, to)

	srcIP := net.ParseIP("127.0.0.1")
	dstIP := srcIP

	// map all ports
	for i := from; i < to; i++ {
		_, port := nat.allocSession(srcIP, dstIP, i, i)
		if i != port {
			b.Error("alloc session failed")
		}
	}

	// release all sessions
	now := time.Now().Unix() + NatSessionLifeSeconds
	nat.clearExpiredSessions(now)
	if nat.count() != 0 {
		b.Error("release session failed")
	}
}

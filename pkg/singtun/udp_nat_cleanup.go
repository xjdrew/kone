package tun

import (
	"container/heap"
	"os"
	"sync"
	"time"
)

const (
	udpNatStateCreated uint32 = iota
	udpNatStateStarted
	udpNatStateClosed
)

func (s *UDPNat) Start() error {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	switch s.state.Load() {
	case udpNatStateCreated:
		if s.interfaceFinder != nil {
			s.interfaceElement = s.interfaceFinder.RegisterInterfaceUpdateCallback(s.updateInterfaces)
			s.reloadInterfaces()
		}
		s.state.Store(udpNatStateStarted)
		s.cleanupWait.Add(1)
		go s.cleanupLoop()
		return nil
	case udpNatStateStarted:
		return nil
	default:
		return os.ErrClosed
	}
}

type udpNatCleanupEntry struct {
	conn     *udpNatConn
	deadline time.Time
	index    int
}

type udpNatCleanupQueue struct {
	service *UDPNat
	access  sync.Mutex
	wake    chan struct{}
	entries udpNatCleanupHeap
}

func newUDPNatCleanupQueue(service *UDPNat) *udpNatCleanupQueue {
	queue := &udpNatCleanupQueue{
		service: service,
		wake:    make(chan struct{}, 1),
	}
	return queue
}

func (q *udpNatCleanupQueue) notify() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *udpNatCleanupQueue) addOrUpdate(entry *udpNatCleanupEntry, deadline time.Time) {
	if entry == nil || q.service.state.Load() == udpNatStateClosed {
		return
	}
	q.access.Lock()
	now := time.Now()
	if entry.conn.isClosed() && deadline.After(now) {
		deadline = now
	}
	entry.deadline = deadline
	if entry.index == -1 {
		heap.Push(&q.entries, entry)
	} else {
		heap.Fix(&q.entries, entry.index)
	}
	q.access.Unlock()
	q.notify()
}

func (q *udpNatCleanupQueue) remove(entry *udpNatCleanupEntry) {
	if entry == nil {
		return
	}
	q.access.Lock()
	if entry.index != -1 {
		heap.Remove(&q.entries, entry.index)
	}
	q.access.Unlock()
	q.notify()
}

func (q *udpNatCleanupQueue) next() (time.Time, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	if len(q.entries) == 0 {
		return time.Time{}, false
	}
	return q.entries[0].deadline, true
}

func (q *udpNatCleanupQueue) popDue(now time.Time) *udpNatCleanupEntry {
	q.access.Lock()
	defer q.access.Unlock()
	if len(q.entries) == 0 || q.entries[0].deadline.After(now) {
		return nil
	}
	return heap.Pop(&q.entries).(*udpNatCleanupEntry)
}

func (q *udpNatCleanupQueue) clear() {
	q.access.Lock()
	for _, entry := range q.entries {
		entry.index = -1
	}
	clear(q.entries)
	q.entries = nil
	q.access.Unlock()
	q.notify()
}

type udpNatCleanupHeap []*udpNatCleanupEntry

func (h udpNatCleanupHeap) Len() int {
	return len(h)
}

func (h udpNatCleanupHeap) Less(i int, j int) bool {
	return h[i].deadline.Before(h[j].deadline)
}

func (h udpNatCleanupHeap) Swap(i int, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *udpNatCleanupHeap) Push(value any) {
	entry := value.(*udpNatCleanupEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *udpNatCleanupHeap) Pop() any {
	oldItems := *h
	lastIndex := len(oldItems) - 1
	entry := oldItems[lastIndex]
	oldItems[lastIndex] = nil
	entry.index = -1
	*h = oldItems[:lastIndex]
	return entry
}

func (s *UDPNat) cleanupLoop() {
	defer s.cleanupWait.Done()
	timer := time.NewTimer(time.Hour)
	stopUDPNatCleanupTimer(timer)
	defer timer.Stop()
	for {
		select {
		case <-s.cleanup.wake:
		default:
		}
		deadline, loaded := s.cleanup.next()
		if !loaded {
			select {
			case <-s.cleanupDone:
				return
			case <-s.cleanup.wake:
				continue
			}
		}
		waitDuration := time.Until(deadline)
		if waitDuration > 0 {
			timer.Reset(waitDuration)
			select {
			case <-s.cleanupDone:
				stopUDPNatCleanupTimer(timer)
				return
			case <-s.cleanup.wake:
				stopUDPNatCleanupTimer(timer)
				continue
			case <-timer.C:
			}
		}
		for {
			entry := s.cleanup.popDue(time.Now())
			if entry == nil {
				break
			}
			s.cleanupEntry(entry)
		}
	}
}

func (s *UDPNat) cleanupEntry(entry *udpNatCleanupEntry) {
	conn, lifetime, loaded := s.cache.PeekWithLifetime(entry.conn.key)
	if !loaded || conn != entry.conn {
		return
	}
	if lifetime.UnixMilli() == 0 {
		return
	}
	if conn.isClosed() {
		lifetime = time.Now()
	}
	s.cleanup.addOrUpdate(entry, lifetime)
}

func stopUDPNatCleanupTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

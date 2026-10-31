package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/canceler"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/memory"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type NATMapping uint8

const (
	NATMappingEndpointIndependent NATMapping = iota
	NATMappingAddressDependent
	NATMappingAddressAndPortDependent
)

type NATFiltering uint8

const (
	NATFilteringEndpointIndependent NATFiltering = iota
	NATFilteringAddressDependent
	NATFilteringAddressAndPortDependent
)

type UDPNatPrepareFunc func(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc)

type UDPNatOptions struct {
	Handler   N.UDPConnectionHandlerEx
	Prepare   UDPNatPrepareFunc
	Timeout   time.Duration
	Shared    bool
	Mapping   NATMapping
	Filtering NATFiltering
	MaxSize   uint32

	InterfaceFinder  control.InterfaceFinder
	ExcludeInterface []string
}

type udpNatSessionKey struct {
	sourceAddr      netip.Addr
	destinationAddr netip.Addr
	sourcePort      uint16
	destinationPort uint16
	interfaceIndex  uint32
}

type udpNatFilterKey struct {
	sessionID uint64
	peer      netip.AddrPort
}

type udpNatEgressEntry struct {
	prefix         netip.Prefix
	interfaceIndex uint32
}

const udpNatEgressLinearThreshold = 8

type udpNatEgressBuckets struct {
	inet4 [256][]udpNatEgressEntry
	inet6 [256][]udpNatEgressEntry
}

type udpNatEgressTable struct {
	entries []udpNatEgressEntry
	buckets *udpNatEgressBuckets
}

type UDPNat struct {
	handler             N.UDPConnectionHandlerEx
	prepare             UDPNatPrepareFunc
	timeout             time.Duration
	mapping             NATMapping
	filtering           NATFiltering
	cache               *freelru.Cache[udpNatSessionKey, *udpNatConn]
	filterCache         *freelru.Cache[udpNatFilterKey, *udpNatConn]
	nextFilterSessionID atomic.Uint64
	interfaceFinder     control.InterfaceFinder
	excludeInterface    []string
	interfaceElement    *list.Element[control.InterfaceUpdateCallback]
	egress              atomic.Pointer[udpNatEgressTable]
	classAccess         sync.Mutex
	classConns          map[uint32]map[*udpNatConn]struct{}
	cleanup             *udpNatCleanupQueue
	state               atomic.Uint32
	lifecycleAccess     sync.Mutex
	closeOnce           sync.Once
	cleanupDone         chan struct{}
	cleanupWait         sync.WaitGroup
}

func NewUDPNat(options UDPNatOptions) *UDPNat {
	if options.Timeout == 0 {
		panic("invalid timeout")
	}
	maxSize := options.MaxSize
	if maxSize == 0 {
		if runtime.GOOS == "ios" {
			maxSize = 4096
		} else if totalMemory := memory.Total(); totalMemory == 0 {
			maxSize = 16384
		} else {
			maxSize = uint32(min(max(totalMemory/16384, 4096), 16384))
		}
	}
	hasher := maphash.NewHasher[udpNatSessionKey]()
	cache := common.Must1(freelru.New[udpNatSessionKey, *udpNatConn](maxSize, hasher.Hash32, options.Shared))
	var filterCache *freelru.Cache[udpNatFilterKey, *udpNatConn]
	if NATMapping(options.Filtering) > options.Mapping {
		filterHasher := maphash.NewHasher[udpNatFilterKey]()
		filterCache = common.Must1(freelru.New[udpNatFilterKey, *udpNatConn](maxSize, filterHasher.Hash32, options.Shared))
	}
	service := &UDPNat{
		handler:          options.Handler,
		prepare:          options.Prepare,
		timeout:          options.Timeout,
		mapping:          options.Mapping,
		filtering:        options.Filtering,
		cache:            cache,
		filterCache:      filterCache,
		interfaceFinder:  options.InterfaceFinder,
		excludeInterface: options.ExcludeInterface,
		classConns:       make(map[uint32]map[*udpNatConn]struct{}),
		cleanupDone:      make(chan struct{}),
	}
	service.cleanup = newUDPNatCleanupQueue(service)
	cache.SetLifetime(options.Timeout)
	cache.SetHealthCheck(func(_ udpNatSessionKey, conn *udpNatConn) bool {
		select {
		case <-conn.doneChan:
			return false
		default:
			return true
		}
	})
	cache.SetOnEvict(func(_ udpNatSessionKey, conn *udpNatConn) {
		conn.closeFromCache()
	})
	if filterCache != nil {
		filterCache.SetOnEvict(func(key udpNatFilterKey, conn *udpNatConn) {
			conn.removeFilterPeer(key.peer)
		})
	}
	return service
}

func (s *UDPNat) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycleAccess.Lock()
		previousState := s.state.Swap(udpNatStateClosed)
		if previousState == udpNatStateStarted {
			close(s.cleanupDone)
		}
		s.lifecycleAccess.Unlock()
		if previousState == udpNatStateStarted {
			s.cleanupWait.Wait()
		}
		if s.interfaceElement != nil {
			s.interfaceFinder.UnregisterInterfaceUpdateCallback(s.interfaceElement)
			s.interfaceElement = nil
		}
		s.cache.Purge()
		if s.filterCache != nil {
			s.filterCache.Purge()
		}
		s.cleanup.clear()
	})
	return nil
}

func (s *UDPNat) reloadInterfaces() {
	s.updateInterfaces(s.interfaceFinder.Interfaces())
}

func (s *UDPNat) updateInterfaces(interfaces []control.Interface) {
	var entries []udpNatEgressEntry
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 ||
			networkInterface.Flags&net.FlagLoopback != 0 ||
			networkInterface.Flags&net.FlagPointToPoint != 0 ||
			networkInterface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if slices.Contains(s.excludeInterface, networkInterface.Name) {
			continue
		}
		for _, prefix := range networkInterface.Addresses {
			if !prefix.Addr().IsGlobalUnicast() {
				continue
			}
			entries = append(entries, udpNatEgressEntry{prefix.Masked(), uint32(networkInterface.Index)})
		}
	}
	s.egress.Store(newUDPNatEgressTable(entries))
	var closeConns []*udpNatConn
	s.classAccess.Lock()
	for interfaceIndex, conns := range s.classConns {
		if !slices.ContainsFunc(entries, func(entry udpNatEgressEntry) bool {
			return entry.interfaceIndex == interfaceIndex
		}) {
			for conn := range conns {
				closeConns = append(closeConns, conn)
			}
			delete(s.classConns, interfaceIndex)
		}
	}
	s.classAccess.Unlock()
	for _, conn := range closeConns {
		conn.Close()
	}
}

func (s *UDPNat) classify(destination M.Socksaddr) uint32 {
	table := s.egress.Load()
	if table == nil || !destination.IsIP() {
		return 0
	}
	return table.lookup(destination.Addr.Unmap())
}

func newUDPNatEgressTable(entries []udpNatEgressEntry) *udpNatEgressTable {
	entries = slices.Clone(entries)
	slices.SortStableFunc(entries, func(a, b udpNatEgressEntry) int {
		return b.prefix.Bits() - a.prefix.Bits()
	})
	table := &udpNatEgressTable{entries: entries}
	if len(entries) <= udpNatEgressLinearThreshold {
		return table
	}
	buckets := new(udpNatEgressBuckets)
	for _, entry := range entries {
		address := entry.prefix.Addr().Unmap()
		bits := entry.prefix.Bits()
		var target *[256][]udpNatEgressEntry
		var firstByte byte
		if address.Is4() {
			target = &buckets.inet4
			firstByte = address.As4()[0]
		} else {
			target = &buckets.inet6
			firstByte = address.As16()[0]
		}
		if bits >= 8 {
			target[firstByte] = append(target[firstByte], entry)
			continue
		}
		var mask byte
		if bits > 0 {
			mask = ^byte(0) << (8 - bits)
		}
		firstByte &= mask
		for index := 0; index < 1<<(8-bits); index++ {
			bucketIndex := firstByte + byte(index)
			target[bucketIndex] = append(target[bucketIndex], entry)
		}
	}
	table.buckets = buckets
	return table
}

func (t *udpNatEgressTable) lookup(address netip.Addr) uint32 {
	entries := t.entries
	if t.buckets != nil {
		if address.Is4() {
			entries = t.buckets.inet4[address.As4()[0]]
		} else {
			entries = t.buckets.inet6[address.As16()[0]]
		}
	}
	for _, entry := range entries {
		if entry.prefix.Contains(address) {
			return entry.interfaceIndex
		}
	}
	return 0
}

func (s *UDPNat) registerClass(conn *udpNatConn) {
	s.classAccess.Lock()
	conns := s.classConns[conn.interfaceIndex]
	if conns == nil {
		conns = make(map[*udpNatConn]struct{})
		s.classConns[conn.interfaceIndex] = conns
	}
	conns[conn] = struct{}{}
	s.classAccess.Unlock()
}

func (s *UDPNat) unregisterClass(conn *udpNatConn) {
	s.classAccess.Lock()
	conns := s.classConns[conn.interfaceIndex]
	if conns != nil {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(s.classConns, conn.interfaceIndex)
		}
	}
	s.classAccess.Unlock()
}

func (s *UDPNat) NewPacket(bufferSlices [][]byte, source M.Socksaddr, destination M.Socksaddr, userData any) {
	conn, ok := s.getOrCreateConn(source, destination, userData)
	if !ok {
		return
	}
	readWaitOptions := conn.loadReadWaitOptions()
	var dataLen int
	for _, bufferSlice := range bufferSlices {
		dataLen += len(bufferSlice)
	}
	buffer := readWaitOptions.NewBufferSize(dataLen)
	for _, bufferSlice := range bufferSlices {
		buffer.Write(bufferSlice)
	}
	readWaitOptions.PostReturn(buffer)
	conn.enqueue(buffer, destination)
}

func (s *UDPNat) getOrCreateConn(source M.Socksaddr, destination M.Socksaddr, userData any) (*udpNatConn, bool) {
	if s.state.Load() != udpNatStateStarted {
		return nil, false
	}
	key := udpNatSessionKey{
		sourceAddr: source.Addr.Unmap(),
		sourcePort: source.Port,
	}
	switch s.mapping {
	case NATMappingEndpointIndependent:
		key.interfaceIndex = s.classify(destination)
	case NATMappingAddressDependent:
		key.destinationAddr = destination.Addr.Unmap()
	case NATMappingAddressAndPortDependent:
		key.destinationAddr = destination.Addr.Unmap()
		key.destinationPort = destination.Port
	}
	var (
		newContext context.Context
		newOnClose N.CloseHandlerFunc
	)
	conn, loaded, ok := s.cache.GetAndRefreshOrAdd(key, func() (*udpNatConn, bool) {
		ok, ctx, writer, onClose := s.prepare(source, destination, userData)
		if !ok {
			return nil, false
		}
		newConn := &udpNatConn{
			service:      s,
			key:          key,
			writer:       writer,
			localAddr:    source,
			packetChan:   make(chan *N.PacketBuffer, 64),
			doneChan:     make(chan struct{}),
			readDeadline: pipe.MakeDeadline(),
		}
		newConn.cleanupEntry = &udpNatCleanupEntry{
			conn:  newConn,
			index: -1,
		}
		if s.filtering != NATFilteringEndpointIndependent {
			if destination.IsIP() {
				newConn.filterPeer = s.filterPeer(destination)
				newConn.filterPeerValid = true
			}
			if s.filterCache != nil {
				filterSessionID := s.nextFilterSessionID.Add(1)
				if filterSessionID == 0 {
					filterSessionID = s.nextFilterSessionID.Add(1)
				}
				newConn.filterSessionID = filterSessionID
			}
		}
		interfaceIndex := key.interfaceIndex
		if s.mapping != NATMappingEndpointIndependent {
			interfaceIndex = s.classify(destination)
		}
		if interfaceIndex != 0 {
			newConn.interfaceIndex = interfaceIndex
			s.registerClass(newConn)
		}
		newContext = ctx
		newOnClose = onClose
		return newConn, true
	})
	if !ok {
		return nil, false
	}
	if s.state.Load() != udpNatStateStarted {
		conn.Close()
		s.cache.Peek(key)
		return nil, false
	}
	if !loaded {
		s.cleanup.addOrUpdate(conn.cleanupEntry, time.Now().Add(s.timeout))
		if conn.isClosed() {
			return nil, false
		}
		go s.handler.NewPacketConnectionEx(newContext, conn, source, destination, newOnClose)
	}
	conn.addFilterPeer(destination)
	return conn, true
}

func (c *udpNatConn) enqueue(buffer *buf.Buffer, destination M.Socksaddr) {
	c.packetAccess.RLock()
	select {
	case <-c.doneChan:
		buffer.Release()
		c.packetAccess.RUnlock()
		return
	default:
	}
	packet := N.NewPacketBuffer()
	*packet = N.PacketBuffer{
		Buffer:      buffer,
		Destination: destination,
	}
	select {
	case c.packetChan <- packet:
	default:
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
	c.packetAccess.RUnlock()
}

func (s *UDPNat) NewPacketBatch(buffers []*buf.Buffer, sources []M.Socksaddr, destination M.Socksaddr, userData any) {
	if len(buffers) != len(sources) {
		buf.ReleaseMulti(buffers)
		return
	}
	for index, buffer := range buffers {
		conn, ok := s.getOrCreateConn(sources[index], destination, userData)
		if !ok {
			buffer.Release()
			continue
		}
		readWaitOptions := conn.loadReadWaitOptions()
		conn.enqueue(readWaitOptions.Copy(buffer), destination)
	}
}

func (s *UDPNat) filterPeer(destination M.Socksaddr) netip.AddrPort {
	if s.filtering == NATFilteringAddressDependent {
		return netip.AddrPortFrom(destination.Addr.Unmap(), 0)
	}
	return netip.AddrPortFrom(destination.Addr.Unmap(), destination.Port)
}

func (s *UDPNat) Purge() {
	if s.filterCache != nil {
		s.filterCache.Purge()
	}
	s.cache.Purge()
}

func (s *UDPNat) PurgeExpired() {
	s.cache.PurgeExpired()
}

var (
	_ N.PacketConn                 = (*udpNatConn)(nil)
	_ canceler.PacketConn          = (*udpNatConn)(nil)
	_ N.PacketBatchReadWaitCreator = (*udpNatConn)(nil)
	_ N.PacketBatchWriteCreator    = (*udpNatConn)(nil)
)

type udpNatConn struct {
	service         *UDPNat
	key             udpNatSessionKey
	interfaceIndex  uint32
	writer          N.PacketWriter
	localAddr       M.Socksaddr
	packetChan      chan *N.PacketBuffer
	packetAccess    sync.RWMutex
	closeOnce       sync.Once
	doneChan        chan struct{}
	readDeadline    pipe.Deadline
	readWaitOptions atomic.Pointer[N.ReadWaitOptions]
	readBatch       *udpNatReadBatch
	cleanupEntry    *udpNatCleanupEntry
	filterSessionID uint64
	filterPeer      netip.AddrPort
	filterPeerValid bool
	filterAccess    sync.Mutex
	filterPeers     map[netip.AddrPort]struct{}
}

type udpNatReadBatch struct {
	buffers      []*buf.Buffer
	destinations []M.Socksaddr
}

func (c *udpNatConn) loadReadWaitOptions() N.ReadWaitOptions {
	options := c.readWaitOptions.Load()
	if options == nil {
		return N.ReadWaitOptions{}
	}
	return *options
}

func (c *udpNatConn) addFilterPeer(destination M.Socksaddr) {
	if c.filterSessionID == 0 || !destination.IsIP() {
		return
	}
	key := udpNatFilterKey{
		sessionID: c.filterSessionID,
		peer:      c.service.filterPeer(destination),
	}
	if c.filterPeerValid && c.filterPeer == key.peer {
		return
	}
	if c.isClosed() || c.service.state.Load() != udpNatStateStarted {
		return
	}
	c.service.filterCache.Add(key, c)
	c.filterAccess.Lock()
	if c.isClosed() || c.service.state.Load() != udpNatStateStarted {
		c.filterAccess.Unlock()
		c.service.filterCache.Remove(key)
		return
	}
	if c.filterPeers == nil {
		c.filterPeers = make(map[netip.AddrPort]struct{})
	}
	c.filterPeers[key.peer] = struct{}{}
	c.filterAccess.Unlock()
	filterConn, loaded := c.service.filterCache.Peek(key)
	if !loaded || filterConn != c {
		c.removeFilterPeer(key.peer)
		return
	}
	if c.isClosed() || c.service.state.Load() != udpNatStateStarted {
		c.service.filterCache.Remove(key)
	}
}

func (c *udpNatConn) removeFilterPeer(peer netip.AddrPort) {
	c.filterAccess.Lock()
	delete(c.filterPeers, peer)
	c.filterAccess.Unlock()
}

func (c *udpNatConn) clearFilterPeers() {
	if c.filterSessionID == 0 {
		return
	}
	c.filterAccess.Lock()
	filterPeers := c.filterPeers
	c.filterPeers = nil
	c.filterAccess.Unlock()
	for peer := range filterPeers {
		c.service.filterCache.Remove(udpNatFilterKey{
			sessionID: c.filterSessionID,
			peer:      peer,
		})
	}
}

func (c *udpNatConn) allowPeer(destination M.Socksaddr) bool {
	if c.service.filtering == NATFilteringEndpointIndependent || !destination.IsIP() {
		return true
	}
	peer := c.service.filterPeer(destination)
	if c.filterPeerValid && c.filterPeer == peer {
		return true
	}
	if c.filterSessionID == 0 {
		return false
	}
	filterConn, loaded := c.service.filterCache.Get(udpNatFilterKey{
		sessionID: c.filterSessionID,
		peer:      peer,
	})
	return loaded && filterConn == c
}

func (c *udpNatConn) ReadPacket(buffer *buf.Buffer) (addr M.Socksaddr, err error) {
	select {
	case p := <-c.packetChan:
		_, err = buffer.ReadOnceFrom(p.Buffer)
		destination := p.Destination
		p.Buffer.Release()
		N.PutPacketBuffer(p)
		return destination, err
	case <-c.doneChan:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpNatConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !c.allowPeer(destination) {
		buffer.Release()
		return nil
	}
	return c.writer.WritePacket(buffer, destination)
}

func (c *udpNatConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	if c.service.filtering != NATFilteringEndpointIndependent {
		return nil, false
	}
	if creator, isCreator := c.writer.(N.PacketBatchWriteCreator); isCreator {
		return creator.CreatePacketBatchWriter()
	}
	if writer, isWriter := c.writer.(N.PacketBatchWriter); isWriter {
		return writer, true
	}
	return nil, false
}

func (c *udpNatConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions.Store(&options)
	return false
}

func (c *udpNatConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	return c.waitReadPacket(c.loadReadWaitOptions())
}

func (c *udpNatConn) waitReadPacket(options N.ReadWaitOptions) (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	select {
	case packet := <-c.packetChan:
		buffer = options.Copy(packet.Buffer)
		destination = packet.Destination
		N.PutPacketBuffer(packet)
		return
	case <-c.doneChan:
		return nil, M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return nil, M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpNatConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	return c, true
}

func (c *udpNatConn) WaitReadPackets() (buffers []*buf.Buffer, destinations []M.Socksaddr, err error) {
	options := c.loadReadWaitOptions()
	buffer, destination, err := c.waitReadPacket(options)
	if err != nil {
		return nil, nil, err
	}
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = 1
	}
	batch := c.readBatch
	if batch == nil {
		batch = new(udpNatReadBatch)
		c.readBatch = batch
	} else {
		clear(batch.buffers)
		clear(batch.destinations)
	}
	buffers = batch.buffers[:0]
	destinations = batch.destinations[:0]
	defer func() {
		batch.buffers = buffers
		batch.destinations = destinations
	}()
	buffers = append(buffers, buffer)
	destinations = append(destinations, destination)
	for len(buffers) < batchSize {
		select {
		case packet := <-c.packetChan:
			buffers = append(buffers, options.Copy(packet.Buffer))
			destinations = append(destinations, packet.Destination)
			N.PutPacketBuffer(packet)
		default:
			return
		}
	}
	return
}

func (c *udpNatConn) Timeout() time.Duration {
	rawConn, lifetime, loaded := c.service.cache.PeekWithLifetime(c.key)
	if !loaded || rawConn != c {
		return 0
	}
	if lifetime.UnixMilli() == 0 {
		return 0
	}
	return time.Until(lifetime)
}

func (c *udpNatConn) SetTimeout(timeout time.Duration) bool {
	updated := c.service.cache.UpdateLifetime(c.key, c, timeout)
	if !updated {
		return false
	}
	if timeout == 0 {
		c.service.cleanup.remove(c.cleanupEntry)
	} else {
		c.service.cleanup.addOrUpdate(c.cleanupEntry, time.Now().Add(timeout))
	}
	return true
}

func (c *udpNatConn) Close() error {
	c.close()
	if c.service.state.Load() == udpNatStateStarted {
		c.service.cleanup.addOrUpdate(c.cleanupEntry, time.Now())
	}
	return nil
}

func (c *udpNatConn) close() {
	c.closeOnce.Do(func() {
		c.packetAccess.Lock()
		close(c.doneChan)
		drained := false
		for !drained {
			select {
			case packet := <-c.packetChan:
				packet.Buffer.Release()
				N.PutPacketBuffer(packet)
			default:
				drained = true
			}
		}
		c.packetAccess.Unlock()
		c.clearFilterPeers()
		if c.interfaceIndex != 0 {
			c.service.unregisterClass(c)
		}
	})
}

func (c *udpNatConn) closeFromCache() {
	c.close()
	c.service.cleanup.remove(c.cleanupEntry)
}

func (c *udpNatConn) isClosed() bool {
	select {
	case <-c.doneChan:
		return true
	default:
		return false
	}
}

func (c *udpNatConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *udpNatConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *udpNatConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpNatConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *udpNatConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpNatConn) Upstream() any {
	return c.writer
}

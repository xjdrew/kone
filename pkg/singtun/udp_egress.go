package tun

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

const udpEgressBufferSize = 65535

type UDPEgressPoolOptions struct {
	Logger           logger.Logger
	Network          string
	Control          control.Func
	InterfaceFinder  control.InterfaceFinder
	InterfaceMonitor DefaultInterfaceMonitor
	ExcludeInterface string
	IsExempt         func() bool
}

type UDPEgressPool struct {
	logger               logger.Logger
	network              string
	control              control.Func
	interfaceFinder      control.InterfaceFinder
	interfaceMonitor     DefaultInterfaceMonitor
	excludeInterface     string
	isExempt             func() bool
	access               sync.Mutex
	port                 uint16
	anchorInterfaceIndex int
	receiveDone          chan struct{}
	members              map[udpEgressSpec]*udpEgressMember
	state                atomic.Pointer[[]*udpEgressMember]
	packetChan           chan udpEgressPacket
	memberReaders        sync.WaitGroup
	finderElement        *list.Element[control.InterfaceUpdateCallback]
}

type udpEgressSpec struct {
	interfaceIndex int
	interfaceName  string
	prefix         netip.Prefix
}

type udpEgressMember struct {
	prefix netip.Prefix
	conn   *net.UDPConn
}

type udpEgressPacket struct {
	buffer *buf.Buffer
	source netip.AddrPort
}

func NewUDPEgressPool(options UDPEgressPoolOptions) *UDPEgressPool {
	return &UDPEgressPool{
		logger:               options.Logger,
		network:              options.Network,
		control:              options.Control,
		interfaceFinder:      options.InterfaceFinder,
		interfaceMonitor:     options.InterfaceMonitor,
		excludeInterface:     options.ExcludeInterface,
		isExempt:             options.IsExempt,
		anchorInterfaceIndex: -1,
		members:              make(map[udpEgressSpec]*udpEgressMember),
		packetChan:           make(chan udpEgressPacket, 128),
	}
}

func (p *UDPEgressPool) Close() {
	p.SetEgressPort(0)
	p.access.Lock()
	defer p.access.Unlock()
	if p.finderElement != nil {
		p.interfaceFinder.UnregisterInterfaceUpdateCallback(p.finderElement)
		p.finderElement = nil
	}
}

func (p *UDPEgressPool) SetEgressPort(port uint16) bool {
	p.access.Lock()
	defer p.access.Unlock()
	if p.port == port {
		return p.state.Load() != nil
	}
	if p.receiveDone != nil {
		close(p.receiveDone)
		p.receiveDone = nil
	}
	p.port = 0
	p.state.Store(nil)
	for spec, member := range p.members {
		delete(p.members, spec)
		member.conn.Close()
	}
	p.memberReaders.Wait()
	for {
		select {
		case packet := <-p.packetChan:
			packet.buffer.Release()
		default:
			goto drained
		}
	}
drained:
	p.anchorInterfaceIndex = -1
	if port == 0 {
		return false
	}
	p.port = port
	defaultInterface := p.interfaceMonitor.DefaultInterface()
	if defaultInterface != nil {
		p.anchorInterfaceIndex = defaultInterface.Index
	}
	p.receiveDone = make(chan struct{})
	if p.finderElement == nil {
		p.finderElement = p.interfaceFinder.RegisterInterfaceUpdateCallback(func(interfaces []control.Interface) {
			p.access.Lock()
			defer p.access.Unlock()
			p.rebuildLocked()
		})
	}
	p.rebuildLocked()
	return p.state.Load() != nil
}

func (p *UDPEgressPool) LookupEgress(destination netip.AddrPort) *net.UDPConn {
	members := p.state.Load()
	if members == nil {
		return nil
	}
	address := destination.Addr().Unmap()
	for _, member := range *members {
		if member.prefix.Contains(address) {
			return member.conn
		}
	}
	return nil
}

func (p *UDPEgressPool) ReceiveEgress(buffer []byte) (int, netip.AddrPort, error) {
	p.access.Lock()
	receiveDone := p.receiveDone
	p.access.Unlock()
	if receiveDone == nil {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	select {
	case <-receiveDone:
		return 0, netip.AddrPort{}, net.ErrClosed
	default:
	}
	select {
	case packet := <-p.packetChan:
		copied := copy(buffer, packet.buffer.Bytes())
		packet.buffer.Release()
		return copied, packet.source, nil
	case <-receiveDone:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (p *UDPEgressPool) rebuildLocked() {
	if p.port == 0 {
		return
	}
	specs := make(map[udpEgressSpec]struct{})
	if !p.isExempt() {
		for _, networkInterface := range p.interfaceFinder.Interfaces() {
			if networkInterface.Flags&net.FlagUp == 0 ||
				networkInterface.Flags&net.FlagLoopback != 0 ||
				networkInterface.Flags&net.FlagPointToPoint != 0 ||
				networkInterface.Flags&net.FlagBroadcast == 0 ||
				networkInterface.Index == p.anchorInterfaceIndex ||
				networkInterface.Name == p.excludeInterface {
				continue
			}
			for _, prefix := range networkInterface.Addresses {
				if !prefix.Addr().IsGlobalUnicast() {
					continue
				}
				if p.network == "udp4" && !prefix.Addr().Is4() {
					continue
				}
				if p.network == "udp6" && prefix.Addr().Is4() {
					continue
				}
				specs[udpEgressSpec{
					interfaceIndex: networkInterface.Index,
					interfaceName:  networkInterface.Name,
					prefix:         prefix,
				}] = struct{}{}
			}
		}
	}
	for spec, member := range p.members {
		_, loaded := specs[spec]
		if loaded {
			continue
		}
		delete(p.members, spec)
		member.conn.Close()
	}
	for spec := range specs {
		_, loaded := p.members[spec]
		if loaded {
			continue
		}
		memberConn, err := p.listenMember(spec)
		if err != nil {
			p.logger.Warn(E.Cause(err, "listen egress member on ", spec.interfaceName, " (", spec.prefix.Addr(), ")"))
			continue
		}
		member := &udpEgressMember{
			prefix: spec.prefix.Masked(),
			conn:   memberConn,
		}
		p.members[spec] = member
		p.memberReaders.Add(1)
		go p.readMember(member, p.receiveDone)
	}
	members := make([]*udpEgressMember, 0, len(p.members))
	for _, member := range p.members {
		members = append(members, member)
	}
	slices.SortFunc(members, func(firstMember, secondMember *udpEgressMember) int {
		return secondMember.prefix.Bits() - firstMember.prefix.Bits()
	})
	if len(members) == 0 {
		p.state.Store(nil)
	} else {
		p.state.Store(&members)
	}
}

func (p *UDPEgressPool) listenMember(spec udpEgressSpec) (*net.UDPConn, error) {
	var listenConfig net.ListenConfig
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		listenConfig.Control = control.ReuseAddrOnly()
	}
	listenConfig.Control = control.Append(listenConfig.Control, control.DisableUDPNetReset())
	listenConfig.Control = control.Append(listenConfig.Control, control.BindToInterface(p.interfaceFinder, spec.interfaceName, spec.interfaceIndex))
	listenConfig.Control = control.Append(listenConfig.Control, p.control)
	var network string
	if spec.prefix.Addr().Is4() {
		network = "udp4"
	} else {
		network = "udp6"
	}
	packetConn, err := listenConfig.ListenPacket(context.Background(), network, netip.AddrPortFrom(spec.prefix.Addr(), p.port).String())
	if err != nil {
		return nil, err
	}
	return packetConn.(*net.UDPConn), nil
}

func (p *UDPEgressPool) readMember(member *udpEgressMember, doneChan <-chan struct{}) {
	defer p.memberReaders.Done()
	for {
		buffer := buf.NewSize(udpEgressBufferSize)
		dataLength, source, err := member.conn.ReadFromUDPAddrPort(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			return
		}
		buffer.Extend(dataLength)
		select {
		case p.packetChan <- udpEgressPacket{buffer: buffer, source: source}:
		case <-doneChan:
			buffer.Release()
			return
		default:
			buffer.Release()
		}
	}
}

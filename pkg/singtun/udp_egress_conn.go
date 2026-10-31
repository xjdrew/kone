package tun

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type UDPEgressConn struct {
	anchor     *net.UDPConn
	pool       *UDPEgressPool
	packetChan chan udpEgressConnPacket
	doneChan   chan struct{}
	closeOnce  sync.Once
	readWait   sync.WaitGroup
}

type udpEgressConnPacket struct {
	buffer *buf.Buffer
	source netip.AddrPort
	err    error
}

func NewUDPEgressConn(anchor *net.UDPConn, pool *UDPEgressPool) *UDPEgressConn {
	conn := &UDPEgressConn{
		anchor:     anchor,
		pool:       pool,
		packetChan: make(chan udpEgressConnPacket, 64),
		doneChan:   make(chan struct{}),
	}
	conn.readWait.Add(2)
	go conn.read(anchor.ReadFromUDPAddrPort)
	go conn.read(pool.ReceiveEgress)
	return conn
}

func (c *UDPEgressConn) read(readPacket func([]byte) (int, netip.AddrPort, error)) {
	defer c.readWait.Done()
	for {
		buffer := buf.NewSize(udpEgressBufferSize)
		dataLength, source, err := readPacket(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			if E.IsClosed(err) {
				return
			}
			select {
			case c.packetChan <- udpEgressConnPacket{err: err}:
			case <-c.doneChan:
				return
			}
			continue
		}
		buffer.Extend(dataLength)
		select {
		case c.packetChan <- udpEgressConnPacket{buffer: buffer, source: source}:
		case <-c.doneChan:
			buffer.Release()
			return
		}
	}
}

func (c *UDPEgressConn) ReadFromUDPAddrPort(buffer []byte) (int, netip.AddrPort, error) {
	select {
	case packet := <-c.packetChan:
		if packet.err != nil {
			return 0, netip.AddrPort{}, packet.err
		}
		copied := copy(buffer, packet.buffer.Bytes())
		packet.buffer.Release()
		return copied, packet.source, nil
	case <-c.doneChan:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *UDPEgressConn) WriteToUDPAddrPort(buffer []byte, destination netip.AddrPort) (int, error) {
	memberConn := c.pool.LookupEgress(destination)
	if memberConn != nil {
		return memberConn.WriteToUDPAddrPort(buffer, destination)
	}
	return c.anchor.WriteToUDPAddrPort(buffer, destination)
}

func (c *UDPEgressConn) LocalAddr() net.Addr {
	return c.anchor.LocalAddr()
}

func (c *UDPEgressConn) SetDeadline(t time.Time) error {
	return c.anchor.SetDeadline(t)
}

func (c *UDPEgressConn) SetReadDeadline(t time.Time) error {
	return c.anchor.SetReadDeadline(t)
}

func (c *UDPEgressConn) SetWriteDeadline(t time.Time) error {
	return c.anchor.SetWriteDeadline(t)
}

func (c *UDPEgressConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.doneChan)
		c.anchor.Close()
		c.pool.Close()
		c.readWait.Wait()
		for {
			select {
			case packet := <-c.packetChan:
				if packet.buffer != nil {
					packet.buffer.Release()
				}
			default:
				return
			}
		}
	})
	return nil
}

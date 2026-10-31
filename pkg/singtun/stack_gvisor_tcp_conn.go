//go:build with_gvisor

package tun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/sagernet/gvisor/pkg/sync"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/waiter"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ net.Conn     = (*gTCPConn)(nil)
	_ N.ReadWaiter = (*gTCPConn)(nil)
)

type gTCPConn struct {
	gTCPDeadline

	wq *waiter.Queue
	ep tcpip.Endpoint

	localAddr  net.Addr
	remoteAddr net.Addr

	readMu         sync.Mutex
	readWaitOption N.ReadWaitOptions
}

func newGTCPConn(wq *waiter.Queue, ep tcpip.Endpoint, localAddr net.Addr, remoteAddr net.Addr) *gTCPConn {
	conn := &gTCPConn{
		wq:         wq,
		ep:         ep,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	conn.gTCPDeadline.init()
	return conn
}

func (c *gTCPConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOption = options
	return false
}

func (c *gTCPConn) WaitReadBuffer() (*buf.Buffer, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	deadline := c.readCancel()
	for {
		if err := c.waitReadable(deadline); err != nil {
			return nil, err
		}
		buffer := c.readWaitOption.NewBuffer()
		writer := tcpip.SliceWriter(buffer.FreeBytes())
		result, err := c.ep.Read(&writer, tcpip.ReadOptions{})
		if _, wouldBlock := err.(*tcpip.ErrWouldBlock); wouldBlock {
			buffer.Release()
			continue
		}
		if err != nil {
			buffer.Release()
			return nil, c.translateReadError(err)
		}
		if result.Count == 0 {
			buffer.Release()
			continue
		}
		buffer.Truncate(result.Count)
		c.readWaitOption.PostReturn(buffer)
		c.ep.ModerateRecvBuf(result.Count)
		return buffer, nil
	}
}

func (c *gTCPConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	writer := tcpip.SliceWriter(b)
	n, err := c.readTo(&writer, c.readCancel())
	if n != 0 {
		c.ep.ModerateRecvBuf(n)
	}
	return n, err
}

func (c *gTCPConn) readTo(writer io.Writer, deadline <-chan struct{}) (int, error) {
	select {
	case <-deadline:
		return 0, c.newOpError("read", os.ErrDeadlineExceeded)
	default:
	}

	result, err := c.ep.Read(writer, tcpip.ReadOptions{})
	if _, wouldBlock := err.(*tcpip.ErrWouldBlock); wouldBlock {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		c.wq.EventRegister(&waitEntry)
		defer c.wq.EventUnregister(&waitEntry)
		for {
			result, err = c.ep.Read(writer, tcpip.ReadOptions{})
			if _, wouldBlock = err.(*tcpip.ErrWouldBlock); !wouldBlock {
				break
			}
			select {
			case <-deadline:
				return 0, c.newOpError("read", os.ErrDeadlineExceeded)
			case <-notifyCh:
			}
		}
	}

	if err != nil {
		return 0, c.translateReadError(err)
	}
	return result.Count, nil
}

func (c *gTCPConn) waitReadable(deadline <-chan struct{}) error {
	select {
	case <-deadline:
		return c.newOpError("read", os.ErrDeadlineExceeded)
	default:
	}
	if c.ep.Readiness(waiter.ReadableEvents)&waiter.ReadableEvents != 0 {
		return nil
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	c.wq.EventRegister(&waitEntry)
	defer c.wq.EventUnregister(&waitEntry)
	for c.ep.Readiness(waiter.ReadableEvents)&waiter.ReadableEvents == 0 {
		select {
		case <-deadline:
			return c.newOpError("read", os.ErrDeadlineExceeded)
		case <-notifyCh:
		}
	}
	return nil
}

func (c *gTCPConn) translateReadError(err tcpip.Error) error {
	if _, closed := err.(*tcpip.ErrClosedForReceive); closed {
		return io.EOF
	}
	return c.newOpError("read", gonet.TranslateNetstackError(err))
}

func (c *gTCPConn) Write(b []byte) (int, error) {
	deadline := c.writeCancel()

	select {
	case <-deadline:
		return 0, c.newOpError("write", os.ErrDeadlineExceeded)
	default:
	}

	var (
		reader bytes.Reader
		nBytes int
		entry  waiter.Entry
		ch     <-chan struct{}
	)
	for nBytes != len(b) {
		reader.Reset(b[nBytes:])
		n, err := c.ep.Write(&reader, tcpip.WriteOptions{})
		nBytes += int(n)
		switch err.(type) {
		case nil:
		case *tcpip.ErrWouldBlock:
			if ch == nil {
				entry, ch = waiter.NewChannelEntry(waiter.WritableEvents)
				c.wq.EventRegister(&entry)
				defer c.wq.EventUnregister(&entry)
			} else {
				select {
				case <-deadline:
					return nBytes, c.newOpError("write", os.ErrDeadlineExceeded)
				case <-ch:
					continue
				}
			}
		default:
			return nBytes, c.newOpError("write", gonet.TranslateNetstackError(err))
		}
	}
	return nBytes, nil
}

func (c *gTCPConn) Close() error {
	c.ep.Close()
	return nil
}

func (c *gTCPConn) CloseRead() error {
	if err := c.ep.Shutdown(tcpip.ShutdownRead); err != nil {
		return c.newOpError("close", errors.New(err.String()))
	}
	return nil
}

func (c *gTCPConn) CloseWrite() error {
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		return c.newOpError("close", errors.New(err.String()))
	}
	return nil
}

func (c *gTCPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *gTCPConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *gTCPConn) SetDeadline(t time.Time) error {
	return c.gTCPDeadline.SetDeadline(t)
}

func (c *gTCPConn) SetReadDeadline(t time.Time) error {
	return c.gTCPDeadline.SetReadDeadline(t)
}

func (c *gTCPConn) SetWriteDeadline(t time.Time) error {
	return c.gTCPDeadline.SetWriteDeadline(t)
}

func (c *gTCPConn) newOpError(op string, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "tcp",
		Source: c.localAddr,
		Addr:   c.remoteAddr,
		Err:    err,
	}
}

type gTCPDeadline struct {
	mu sync.Mutex

	readTimer     *time.Timer
	readCancelCh  chan struct{}
	writeTimer    *time.Timer
	writeCancelCh chan struct{}
}

func (d *gTCPDeadline) init() {
	d.readCancelCh = make(chan struct{})
	d.writeCancelCh = make(chan struct{})
}

func (d *gTCPDeadline) readCancel() <-chan struct{} {
	d.mu.Lock()
	cancelCh := d.readCancelCh
	d.mu.Unlock()
	return cancelCh
}

func (d *gTCPDeadline) writeCancel() <-chan struct{} {
	d.mu.Lock()
	cancelCh := d.writeCancelCh
	d.mu.Unlock()
	return cancelCh
}

func (d *gTCPDeadline) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *gTCPDeadline) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *gTCPDeadline) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *gTCPDeadline) setDeadline(cancelCh *chan struct{}, timer **time.Timer, t time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancelCh = make(chan struct{})
	}

	select {
	case <-*cancelCh:
		*cancelCh = make(chan struct{})
	default:
	}

	if t.IsZero() {
		*timer = nil
		return
	}

	timeout := time.Until(t)
	if timeout <= 0 {
		close(*cancelCh)
		return
	}

	ch := *cancelCh
	*timer = time.AfterFunc(timeout, func() {
		close(ch)
	})
}

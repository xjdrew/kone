//go:build with_gvisor

package tun

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

type gLazyConn struct {
	tcpConn         *gTCPConn
	parentCtx       context.Context
	stack           *stack.Stack
	request         *tcp.ForwarderRequest
	localAddr       net.Addr
	remoteAddr      net.Addr
	handshakeAccess sync.Mutex
	handshakeDone   bool
	handshakeErr    error
}

func (c *gLazyConn) HandshakeContext(ctx context.Context) error {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	if c.handshakeDone {
		return c.handshakeErr
	}
	defer func() {
		c.handshakeDone = true
	}()
	var (
		wq       waiter.Queue
		endpoint tcpip.Endpoint
	)
	var cancel context.CancelFunc
	if parentDone := c.parentCtx.Done(); parentDone != nil {
		var handshakeCtx context.Context
		handshakeCtx, cancel = context.WithCancel(ctx)
		go func() {
			select {
			case <-parentDone:
				wq.Notify(wq.Events())
			case <-handshakeCtx.Done():
			}
		}()
	}
	endpoint, err := c.request.CreateEndpoint(&wq)
	if cancel != nil {
		cancel()
	}
	if err != nil {
		gErr := gonet.TranslateNetstackError(err)
		c.handshakeErr = gErr
		c.request.Complete(true)
		return gErr
	}
	c.request.Complete(false)
	endpoint.SocketOptions().SetKeepAlive(true)
	tcpConn := newGTCPConn(&wq, endpoint, c.localAddr, c.remoteAddr)
	c.tcpConn = tcpConn
	return nil
}

func (c *gLazyConn) HandshakeFailure(err error) error {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	if c.handshakeDone {
		return os.ErrInvalid
	}
	c.request.Complete(true)
	c.handshakeDone = true
	c.handshakeErr = err
	return nil
}

func (c *gLazyConn) HandshakeSuccess() error {
	return c.HandshakeContext(context.Background())
}

func (c *gLazyConn) NeedHandshakeForRead() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return !c.handshakeDone
}

func (c *gLazyConn) NeedHandshakeForWrite() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return !c.handshakeDone
}

func (c *gLazyConn) Read(b []byte) (n int, err error) {
	err = c.HandshakeContext(context.Background())
	if err != nil {
		return
	}
	return c.tcpConn.Read(b)
}

func (c *gLazyConn) Write(b []byte) (n int, err error) {
	err = c.HandshakeContext(context.Background())
	if err != nil {
		return
	}
	return c.tcpConn.Write(b)
}

func (c *gLazyConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *gLazyConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *gLazyConn) SetDeadline(t time.Time) error {
	err := c.HandshakeContext(context.Background())
	if err != nil {
		return err
	}
	return c.tcpConn.SetDeadline(t)
}

func (c *gLazyConn) SetReadDeadline(t time.Time) error {
	err := c.HandshakeContext(context.Background())
	if err != nil {
		return err
	}
	return c.tcpConn.SetReadDeadline(t)
}

func (c *gLazyConn) SetWriteDeadline(t time.Time) error {
	err := c.HandshakeContext(context.Background())
	if err != nil {
		return err
	}
	return c.tcpConn.SetWriteDeadline(t)
}

func (c *gLazyConn) Close() error {
	if c.closeBeforeHandshake() {
		return nil
	}
	return c.tcpConn.Close()
}

func (c *gLazyConn) CloseRead() error {
	if c.closeBeforeHandshake() {
		return nil
	}
	return c.tcpConn.CloseRead()
}

func (c *gLazyConn) CloseWrite() error {
	if c.closeBeforeHandshake() {
		return nil
	}
	return c.tcpConn.CloseWrite()
}

func (c *gLazyConn) closeBeforeHandshake() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	if !c.handshakeDone {
		if c.request != nil {
			c.request.Complete(true)
		}
		c.handshakeErr = net.ErrClosed
		c.handshakeDone = true
		return true
	}
	return c.handshakeErr != nil
}

func (c *gLazyConn) ReaderReplaceable() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return c.handshakeDone && c.handshakeErr == nil
}

func (c *gLazyConn) WriterReplaceable() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return c.handshakeDone && c.handshakeErr == nil
}

func (c *gLazyConn) Upstream() any {
	return c.tcpConn
}

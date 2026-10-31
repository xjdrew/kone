//go:build linux

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type redirectServer struct {
	ctx        context.Context
	handler    N.TCPConnectionHandlerEx
	logger     logger.Logger
	listenAddr netip.Addr
	listener   *net.TCPListener
	inShutdown atomic.Bool
}

func newRedirectServer(ctx context.Context, handler N.TCPConnectionHandlerEx, logger logger.Logger, listenAddr netip.Addr) *redirectServer {
	return &redirectServer{
		ctx:        ctx,
		handler:    handler,
		logger:     logger,
		listenAddr: listenAddr,
	}
}

func (s *redirectServer) Start() error {
	var listenConfig net.ListenConfig
	// listenConfig.KeepAlive = C.TCPKeepAliveInitial
	listenConfig.KeepAlive = 10 * time.Minute
	listener, err := listenConfig.Listen(s.ctx, M.NetworkFromNetAddr("tcp", s.listenAddr), M.SocksaddrFrom(s.listenAddr, 0).String())
	if err != nil {
		return err
	}
	s.listener = listener.(*net.TCPListener)
	go s.loopIn()
	return nil
}

func (s *redirectServer) Close() error {
	s.inShutdown.Store(true)
	return s.listener.Close()
}

func (s *redirectServer) loopIn() {
	var retryDelay time.Duration
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			if s.inShutdown.Load() && E.IsClosed(err) {
				return
			}
			var netError net.Error
			//nolint:staticcheck
			if errors.As(err, &netError) && netError.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
				s.logger.Error("accept: ", err, ": retrying in ", retryDelay)
				time.Sleep(retryDelay)
				continue
			}
			s.listener.Close()
			s.logger.Error("serve error: ", err)
			return
		}
		retryDelay = 0
		source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		destination, err := control.GetOriginalDestination(conn)
		if err != nil {
			_ = conn.SetLinger(0)
			_ = conn.Close()
			s.logger.Error("process redirect connection from ", source, ": invalid connection: ", err)
			continue
		}
		go s.handler.NewConnectionEx(s.ctx, conn, source, M.SocksaddrFromNetIP(destination).Unwrap(), nil)
	}
}

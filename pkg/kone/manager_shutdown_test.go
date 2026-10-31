package kone

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Hold Serve inside Accept after the socket is closed. Shutdown must then
// close its tracked listener before Serve can unregister it: no scheduling
// luck or sleeps are needed to reproduce the original double-close failure.
type heldAcceptListener struct {
	net.Listener
	entered    chan struct{}
	release    <-chan struct{}
	once       sync.Once
	closes     atomic.Int32
	closeError error
}

func (l *heldAcceptListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.entered) })
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.release
	}
	return conn, err
}

func (l *heldAcceptListener) Close() error {
	l.closes.Add(1)
	return errors.Join(l.Listener.Close(), l.closeError)
}

type heldAcceptSockets struct {
	*loopSockets
	listener *heldAcceptListener
}

func (s *heldAcceptSockets) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	listener, err := s.loopSockets.Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	s.listener.Listener = listener
	return s.listener, nil
}

func TestManagerShutdownBeforeServeUnregistersListener(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{name: "normal"}, {name: "close error", err: errors.New("injected listener close failure")}} {
		t.Run(tc.name, func(t *testing.T) {
			network, sockets := newMemoryNetwork(), &loopSockets{}
			one := lifecycleEngine(t, network, sockets)
			released := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(released) }) }
			defer release()
			listener := &heldAcceptListener{entered: make(chan struct{}), release: released, closeError: tc.err}
			one.sockets = &heldAcceptSockets{loopSockets: sockets, listener: listener}
			_, done := runReady(t, one)
			// Shutdown invokes callbacks after closing tracked listeners, before
			// waiting for Serve to exit. Release Accept only after that second
			// Close attempt; waiting for network rollback would deadlock here.
			one.manager.server.RegisterOnShutdown(release)
			select {
			case <-listener.entered:
			case <-time.After(time.Second):
				t.Fatal("HTTP Serve did not enter Accept")
			}
			results := make(chan error, 8)
			for range cap(results) {
				go func() { results <- one.Close() }()
			}
			for range cap(results) {
				select {
				case err := <-results:
					if tc.err == nil {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, tc.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("concurrent Close did not finish")
				}
			}
			if tc.err == nil {
				require.NoError(t, waitRun(t, done))
			} else {
				require.ErrorIs(t, waitRun(t, done), tc.err)
			}
			require.Equal(t, int32(1), listener.closes.Load(), "engine and HTTP server must close the underlying listener once")
			assertReleased(t, network, sockets)
		})
	}
}

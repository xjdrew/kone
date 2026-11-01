package integration

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Fail a live DNS TCP admission only after Ready, so system-DNS guidance has
// actually been installed. This retains late-failure restoration coverage
// without an unrelated unauthenticated management listener.
type failedDNSAdmissionSockets struct {
	net.ListenConfig
	fail chan struct{}
	once sync.Once
}

func newFailedDNSAdmissionSockets() *failedDNSAdmissionSockets {
	return &failedDNSAdmissionSockets{fail: make(chan struct{})}
}

func (s *failedDNSAdmissionSockets) Trigger() { s.once.Do(func() { close(s.fail) }) }

func (s *failedDNSAdmissionSockets) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	listener, err := s.ListenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &failedDNSAdmissionListener{Listener: listener, fail: s.fail, closed: make(chan struct{})}, nil
}

type failedDNSAdmissionListener struct {
	net.Listener
	fail   <-chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (l *failedDNSAdmissionListener) Accept() (net.Conn, error) {
	select {
	case <-l.fail:
		return nil, errors.New("injected late DNS TCP admission failure")
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *failedDNSAdmissionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

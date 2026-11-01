package kone

import (
	"errors"
	"net"
	"sync"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	singtun "github.com/sagernet/sing-tun"
)

type gvisorTun struct {
	*supervisedTun
	native   singtun.GVisorTun
	full     bool
	mu       sync.Mutex
	endpoint *supervisedEndpoint
}

func (t *gvisorTun) WritePacket(p *stack.PacketBuffer) (int, error) {
	if !t.beginIO() {
		return 0, net.ErrClosed
	}
	defer t.ioTasks.Done()
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	n, err := t.native.WritePacket(p)
	t.report(err)
	return n, err
}
func (t *gvisorTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	if !t.full {
		return t.native.NewEndpoint()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.endpoint != nil {
		return nil, stack.NICOptions{}, errors.New("gvisor endpoint already created")
	}
	t.endpoint = newSupervisedEndpoint(t)
	return t.endpoint, stack.NICOptions{}, nil
}

func (t *gvisorTun) closeEndpoint() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.endpoint != nil {
		t.endpoint.stop()
	}
}

func (t *gvisorTun) activateEndpoint() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.endpoint != nil {
		t.endpoint.activate()
	}
}

func (t *gvisorTun) waitEndpoint() {
	t.mu.Lock()
	endpoint := t.endpoint
	t.mu.Unlock()
	if endpoint != nil {
		endpoint.Wait()
	}
}
func stackTun(t *supervisedTun, kind string) (singtun.Tun, error) {
	if kind != StackMixed && kind != StackGVisor {
		return t, nil
	}
	native, ok := t.Tun.(singtun.GVisorTun)
	if !ok {
		return nil, errors.New(kind + " stack unavailable for this device")
	}
	return &gvisorTun{supervisedTun: t, native: native, full: kind == StackGVisor}, nil
}

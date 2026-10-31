//go:build with_gvisor

package kone

import (
	"errors"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	singtun "github.com/sagernet/sing-tun"
	"net"
)

type mixedTun struct {
	*supervisedTun
	native singtun.GVisorTun
}

func (t *mixedTun) WritePacket(p *stack.PacketBuffer) (int, error) {
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
func (t *mixedTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.native.NewEndpoint()
}
func stackTun(t *supervisedTun, kind string) (singtun.Tun, error) {
	if kind != "mixed" {
		return t, nil
	}
	native, ok := t.Tun.(singtun.GVisorTun)
	if !ok {
		return nil, errors.New("mixed stack unavailable for this device")
	}
	return &mixedTun{supervisedTun: t, native: native}, nil
}

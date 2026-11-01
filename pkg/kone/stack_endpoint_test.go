package kone

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	singtun "github.com/sagernet/sing-tun"
	"github.com/stretchr/testify/require"
)

type stackPacketTun struct {
	*stubTun
	packets       chan []byte
	written       chan []byte
	readErrors    chan error
	writeFaults   chan error
	writeErrors   chan error
	endpoints     atomic.Int32
	writeErr      error
	invalidLength bool
}

func (t *stackPacketTun) Read(p []byte) (int, error) {
	select {
	case packet := <-t.packets:
		if t.invalidLength {
			return len(p) + 1, nil
		}
		return copy(p, packet), nil
	case err := <-t.fault:
		if t.readErrors != nil {
			t.readErrors <- err
		}
		return 0, err
	case <-t.closed:
		return 0, net.ErrClosed
	}
}
func (t *stackPacketTun) WritePacket(packet *stack.PacketBuffer) (int, error) {
	select {
	case err := <-t.writeFaults:
		t.writeErrors <- err
		return 0, err
	default:
	}
	if t.writeErr != nil {
		return 0, t.writeErr
	}
	payload := bytes.Join(packet.AsSlices(), nil)
	t.written <- payload
	return len(payload), nil
}
func (t *stackPacketTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	t.endpoints.Add(1)
	return channel.New(1, MTU, ""), stack.NICOptions{}, nil
}

type dispatchedPacket struct {
	protocol tcpip.NetworkProtocolNumber
	metadata tcpip.NetworkProtocolNumber
	data     []byte
}
type packetDispatcher struct{ packets chan dispatchedPacket }

func (d packetDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}
func (d packetDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, packet *stack.PacketBuffer) {
	d.packets <- dispatchedPacket{protocol, packet.NetworkProtocolNumber, bytes.Join(packet.AsSlices(), nil)}
}

func endpointFixture(t *testing.T, configure func(*stackPacketTun)) (*stackPacketTun, *gvisorTun, *supervisedEndpoint, chan error, <-chan dispatchedPacket) {
	t.Helper()
	native := &stackPacketTun{stubTun: &stubTun{memoryDevice: newMemoryDevice()}, packets: make(chan []byte, 8), written: make(chan []byte, 8), readErrors: make(chan error, 8)}
	if configure != nil {
		configure(native)
	}
	failures := make(chan error, 8)
	ctx, cancel := context.WithCancel(context.Background())
	io := &supervisedTun{Tun: native, ctx: ctx, fail: failures}
	wrapped, err := stackTun(io, StackGVisor)
	require.NoError(t, err)
	adapter := wrapped.(*gvisorTun)
	endpoint, _, err := adapter.NewEndpoint()
	require.NoError(t, err)
	e := endpoint.(*supervisedEndpoint)
	packets := make(chan dispatchedPacket, 8)
	e.Attach(packetDispatcher{packets})
	adapter.activateEndpoint()
	t.Cleanup(func() {
		cancel()
		adapter.closeEndpoint()
		native.Close()
		done := make(chan struct{})
		go func() { adapter.waitEndpoint(); io.wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("gvisor packet workers leaked")
		}
	})
	return native, adapter, e, failures, packets
}

func TestGVisorEndpointSupervisesIPv4IPv6AndWrites(t *testing.T) {
	native, adapter, endpoint, failures, delivered := endpointFixture(t, nil)
	// Discard empty/unknown frames; preserve the IP payload after platform
	// framing (macOS has a four-byte address-family prefix).
	native.packets <- nil
	native.packets <- append(make([]byte, singtun.PacketOffset), 0xf0)
	for _, tc := range []struct {
		version  byte
		protocol tcpip.NetworkProtocolNumber
	}{{4, header.IPv4ProtocolNumber}, {6, header.IPv6ProtocolNumber}} {
		payload := bytes.Repeat([]byte{tc.version << 4}, 40)
		native.packets <- append(make([]byte, singtun.PacketOffset), payload...)
		select {
		case packet := <-delivered:
			require.Equal(t, tc.protocol, packet.protocol)
			require.Equal(t, tc.protocol, packet.metadata, "native writeback needs the correct IPv4/IPv6 utun address-family metadata")
			require.Equal(t, payload, packet.data)
		case <-time.After(time.Second):
			t.Fatal("gvisor packet was not delivered")
		}
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("response"))})
	packet.NetworkProtocolNumber = header.IPv4ProtocolNumber
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	n, err := endpoint.WritePackets(packets)
	packet.DecRef()
	require.Nil(t, err)
	require.Equal(t, 1, n)
	select {
	case data := <-native.written:
		require.Equal(t, "response", string(data))
	case <-time.After(time.Second):
		t.Fatal("response was not written")
	}
	require.Empty(t, failures)
	require.Zero(t, native.endpoints.Load(), "full gvisor must not bypass IO supervision through the native FD endpoint")
	_, _, createErr := adapter.NewEndpoint()
	require.ErrorContains(t, createErr, "already created")
	endpoint.Attach(packetDispatcher{make(chan dispatchedPacket, 1)}) // no duplicate pumps
	endpoint.Attach(nil)
	endpoint.Attach(packetDispatcher{make(chan dispatchedPacket, 1)}) // closed is terminal
	require.False(t, endpoint.IsAttached())
}

func TestGVisorEndpointQueueIsBoundedAndStopBeforeAttachIsTerminal(t *testing.T) {
	native := &stackPacketTun{stubTun: &stubTun{memoryDevice: newMemoryDevice()}}
	tun := &gvisorTun{supervisedTun: &supervisedTun{Tun: native, ctx: t.Context(), fail: make(chan error, 1)}, native: native, full: true}
	endpoint := newSupervisedEndpoint(tun)
	defer endpoint.stop()
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, MTU))})
	defer packet.DecRef()
	var list stack.PacketBufferList
	list.PushBack(packet)
	accepted := 0
	for range 300 {
		n, err := endpoint.WritePackets(list)
		accepted += n
		if err != nil {
			require.IsType(t, &tcpip.ErrNoBufferSpace{}, err)
		}
	}
	require.Equal(t, 256, accepted)
	require.Equal(t, 256, endpoint.NumQueued())
	endpoint.stop()
	require.Zero(t, endpoint.NumQueued(), "shutdown releases all retained packet references")
	endpoint.Attach(packetDispatcher{make(chan dispatchedPacket, 1)})
	require.False(t, endpoint.IsAttached())
	endpoint.Wait() // no worker may be started after stop, even before first attach
	_, err := endpoint.WritePackets(list)
	require.IsType(t, &tcpip.ErrClosedForSend{}, err)
}

func TestGVisorEndpointReportsTerminalIOAndRetainsRecoverableRead(t *testing.T) {
	for _, kind := range []string{"read", "write", "invalid-length"} {
		t.Run(kind, func(t *testing.T) {
			failure := errors.New("injected gvisor " + kind)
			native, _, endpoint, failures, _ := endpointFixture(t, func(native *stackPacketTun) {
				if kind == "write" {
					native.writeErr = failure
				}
				native.invalidLength = kind == "invalid-length"
			})
			switch kind {
			case "read":
				native.fault <- failure
			case "write":
				packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45})})
				var list stack.PacketBufferList
				list.PushBack(packet)
				endpoint.WritePackets(list)
				packet.DecRef()
			case "invalid-length":
				native.packets <- []byte{0x45}
			}
			select {
			case err := <-failures:
				if kind == "invalid-length" {
					require.ErrorContains(t, err, "invalid packet length")
				} else {
					require.ErrorIs(t, err, failure)
				}
			case <-time.After(time.Second):
				t.Fatal("terminal gvisor I/O failure was lost")
			}
		})
	}
	native, _, _, failures, delivered := endpointFixture(t, nil)
	native.fault <- syscall.EINTR
	select {
	case <-native.readErrors:
	case <-time.After(time.Second):
		t.Fatal("recoverable read fixture did not reach the TUN boundary")
	}
	native.packets <- append(make([]byte, singtun.PacketOffset), 0x45)
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("recoverable read stopped packet delivery")
	}
	require.Empty(t, failures)
}

func TestGVisorPacketAdapterSelectionAndClosedWrite(t *testing.T) {
	native, adapter, endpoint, _, _ := endpointFixture(t, nil)
	_, err := stackTun(adapter.supervisedTun, StackSystem)
	require.NoError(t, err)
	mixed, err := stackTun(adapter.supervisedTun, StackMixed)
	require.NoError(t, err)
	_, _, err = mixed.(*gvisorTun).NewEndpoint()
	require.NoError(t, err)
	require.Equal(t, int32(1), native.endpoints.Load())
	endpoint.stop()
	native.Close()
	adapter.waitEndpoint()
	adapter.supervisedTun.wait()
	_, err = adapter.WritePacket(nil)
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestGVisorTransientWriteDoesNotStopPacketPump(t *testing.T) {
	native, _, endpoint, failures, _ := endpointFixture(t, func(tun *stackPacketTun) {
		tun.writeFaults = make(chan error, 1)
		tun.writeErrors = make(chan error, 1)
		tun.writeFaults <- syscall.EAGAIN
	})
	write := func(payload string) {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte(payload))})
		var list stack.PacketBufferList
		list.PushBack(packet)
		_, err := endpoint.WritePackets(list)
		packet.DecRef()
		require.Nil(t, err)
	}
	write("temporary congestion")
	select {
	case <-native.writeErrors:
	case <-time.After(time.Second):
		t.Fatal("transient write fault was not exercised")
	}
	write("next response")
	select {
	case payload := <-native.written:
		require.Equal(t, "next response", string(payload))
	case <-time.After(time.Second):
		t.Fatal("transient failure permanently stopped gvisor writes")
	}
	require.Empty(t, failures)
}

func TestFullGVisorStackStartupAndDeviceFailure(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	native := &stackPacketTun{stubTun: &stubTun{memoryDevice: newMemoryDevice()}, packets: make(chan []byte, 1), written: make(chan []byte, 1)}
	device := &singDevice{Tun: native, name: "kone-memory"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures := make(chan error, 1)
	cfg := one.Snapshot().Config.Core
	cfg.Stack = StackGVisor
	stack, err := newSingStack(ctx, device, cfg, one.flows, failures)
	require.NoError(t, err)
	require.NoError(t, stack.Start(), "full gvisor startup requires no kernel TCP listener or real TUN")
	native.fault <- errors.New("memory TUN disconnected")
	select {
	case err := <-failures:
		require.ErrorContains(t, err, "memory TUN disconnected")
	case <-time.After(time.Second):
		t.Fatal("full gvisor lost device failure")
	}
	cancel()
	require.NoError(t, stack.Close())
	require.NoError(t, device.Close())
	stack.(interface{ Wait() }).Wait()
	require.NoError(t, stack.Close())
	require.Equal(t, int32(1), native.closes.Load())
}

func TestGVisorAdmissionWaitsForCompleteStackInitialization(t *testing.T) {
	for _, startupErr := range []error{nil, errors.New("initialization failed after NIC attachment")} {
		t.Run(map[bool]string{true: "success", false: "failure"}[startupErr == nil], func(t *testing.T) {
			native := &stackPacketTun{stubTun: &stubTun{memoryDevice: newMemoryDevice()}, packets: make(chan []byte, 1), written: make(chan []byte, 1)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			io := &supervisedTun{Tun: native, ctx: ctx, fail: make(chan error, 1)}
			adapter := &gvisorTun{supervisedTun: io, native: native, full: true}
			e := newSupervisedEndpoint(adapter)
			adapter.endpoint = e
			delivered := make(chan dispatchedPacket, 1)
			attached, initialize := make(chan struct{}), make(chan struct{})
			delegate := &fixtureStack{start: func() error {
				e.Attach(packetDispatcher{delivered})
				close(attached)
				<-initialize
				return startupErr
			}, close: func() error { e.Attach(nil); return nil }}
			stack := &singStack{packetStack: delegate, io: io, tun: adapter}
			defer func() { cancel(); stack.Close(); native.Close(); stack.Wait() }()
			done := make(chan error, 1)
			go func() { done <- stack.Start() }()
			<-attached
			// Packets may already be waiting on a gateway when CreateNIC
			// attaches. They cannot enter partially initialized TCP handlers.
			native.packets <- append(make([]byte, singtun.PacketOffset), 0x45)
			select {
			case <-delivered:
				t.Error("packet admitted before transport handler initialization")
			case <-time.After(20 * time.Millisecond):
			}
			close(initialize)
			require.ErrorIs(t, <-done, startupErr)
			if startupErr == nil {
				select {
				case <-delivered:
				case <-time.After(time.Second):
					t.Fatal("fully initialized stack did not admit queued packet")
				}
			} else {
				require.NoError(t, stack.Close())
				native.Close()
				stack.Wait()
				require.Empty(t, delivered, "failed startup must never activate packet admission")
			}
		})
	}
}

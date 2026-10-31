package kone

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	singtun "github.com/sagernet/sing-tun"
	"github.com/stretchr/testify/require"
)

type stubTun struct {
	*memoryDevice
	nameErr  error
	closeErr error
}

func (d *stubTun) Name() (string, error)                    { return "kone-test", d.nameErr }
func (d *stubTun) Start() error                             { return nil }
func (d *stubTun) UpdateRouteOptions(singtun.Options) error { return nil }
func (d *stubTun) Close() error                             { d.memoryDevice.Close(); return d.closeErr }

type openResultNetwork struct {
	*memoryNetwork
	result Device
	err    error
}

func (n openResultNetwork) Open(context.Context, CoreConfig) (Device, error) { return n.result, n.err }

func TestFailedOpenTypedNilNeverPanics(t *testing.T) {
	cleanProxyEnv(t)
	for _, typed := range []bool{false, true} {
		for _, original := range []error{nil, errors.New("Wintun access denied")} {
			n := newMemoryNetwork()
			var result Device
			if typed {
				var pointer *memoryDevice
				result = pointer
			}
			one, err := FromConfig(parseTestConfig(t, ""), WithNetwork(openResultNetwork{n, result, original}))
			require.NoError(t, err)
			require.NotPanics(t, func() { err = one.Run(context.Background()) })
			if original != nil {
				require.ErrorIs(t, err, original)
			} else {
				require.ErrorContains(t, err, "nil TUN device")
			}
			require.NoError(t, one.Close())
			require.Empty(t, n.events)
		}
	}
	n := newMemoryNetwork()
	original := errors.New("partial open failed")
	one, err := FromConfig(parseTestConfig(t, ""), WithNetwork(openResultNetwork{n, n.device, original}))
	require.NoError(t, err)
	require.ErrorIs(t, one.Run(context.Background()), original)
	require.Equal(t, int32(1), n.device.closes.Load())
	var network *memoryNetwork
	_, err = FromConfig(parseTestConfig(t, ""), WithNetwork(network))
	require.ErrorContains(t, err, "network is nil")
	var sockets *loopSockets
	_, err = FromConfig(parseTestConfig(t, ""), WithSockets(sockets))
	require.ErrorContains(t, err, "sockets is nil")
}

func TestSingDeviceOpenOwnershipAndErrors(t *testing.T) {
	cfg := CoreConfig{Network: "10.192.0.1/16"}
	failure := errors.New("injected driver failure")
	for _, mode := range []string{"nil", "typed nil", "partial", "name", "canceled", "success", "empty"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tun := &stubTun{memoryDevice: newMemoryDevice()}
			device, err := openSingDevice(ctx, cfg, func(options singtun.Options) (singtun.Tun, error) {
				require.True(t, options.EXP_ExternalConfiguration)
				require.True(t, options.EXP_Exclusive)
				require.True(t, options.EXP_DisableDNSHijack)
				require.Equal(t, uint32(MTU), options.MTU)
				require.NotEmpty(t, options.Name)
				switch mode {
				case "nil":
					return nil, failure
				case "typed nil":
					var pointer *stubTun
					return pointer, failure
				case "partial":
					return tun, failure
				case "name":
					tun.nameErr = failure
				case "canceled":
					cancel()
				case "empty":
					return nil, nil
				}
				return tun, nil
			})
			if mode == "success" {
				require.NoError(t, err)
				require.Equal(t, "kone-test", device.Name())
				require.NoError(t, device.Close())
				require.NoError(t, device.Close())
			} else {
				require.Error(t, err)
				require.Nil(t, device)
			}
			if mode != "nil" && mode != "typed nil" && mode != "empty" {
				require.Equal(t, int32(1), tun.closes.Load())
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := openSingDevice(ctx, cfg, nil)
	require.ErrorIs(t, err, context.Canceled)
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	cfg.Tun = interfaces[0].Name
	_, err = openSingDevice(context.Background(), cfg, nil)
	require.ErrorContains(t, err, "existing interface")
}

func TestProductionSingStackFailureSupervision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("real Windows stack startup is covered by the privileged Wintun CI job")
	}
	cleanProxyEnv(t)
	one := testEngine(t)
	tun := &stubTun{memoryDevice: newMemoryDevice()}
	device := &singDevice{Tun: tun, name: "kone-test"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures := make(chan error, 1)
	cfg := one.Snapshot().Config.Core
	// A real sing-tun system stack can listen on loopback without OS changes.
	cfg.Network = "127.0.0.1/8"
	stack, err := newSingStack(ctx, device, cfg, one.flows, failures)
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	failure := errors.New("device disappeared")
	tun.fault <- failure
	select {
	case err := <-failures:
		require.ErrorIs(t, err, failure)
	case <-time.After(time.Second):
		t.Fatal("dead TUN was not reported")
	}
	cancel()
	require.NoError(t, stack.Close())
	require.NoError(t, stack.Close())
	require.NoError(t, device.Close())
	stack.(interface{ Wait() }).Wait()
	_, err = newSingStack(ctx, newMemoryDevice(), cfg, one.flows, failures)
	require.ErrorContains(t, err, "sing-tun")
	cfg.Stack = "invalid"
	_, err = newSingStack(ctx, device, cfg, one.flows, failures)
	require.ErrorContains(t, err, "unknown stack")
}

func TestSupervisedIOAndLogger(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	failures := make(chan error, 1)
	tun := &stubTun{memoryDevice: newMemoryDevice()}
	wrapped := &supervisedTun{Tun: tun, ctx: ctx, fail: failures}
	n, err := wrapped.Write([]byte("packet"))
	require.NoError(t, err)
	require.Equal(t, 6, n)
	wrapped.report(io.ErrUnexpectedEOF)
	require.ErrorIs(t, <-failures, io.ErrUnexpectedEOF)
	cancel()
	wrapped.report(io.ErrClosedPipe)
	require.Empty(t, failures)
	tun.Close()
	wrapped.wait()
	_, err = wrapped.Read(nil)
	require.ErrorIs(t, err, net.ErrClosed)
	logger := stackLogger{fail: failures}
	logger.Trace("trace")
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warning")
	logger.Error("error")
	require.NotPanics(t, func() { logger.Fatal("fatal"); logger.Panic("panic") })
	require.ErrorContains(t, <-failures, "fatal")
	_, err = stackTun(wrapped, "mixed")
	require.Error(t, err) // this fake device has no gVisor endpoint in either build
}

func TestStackStartupFailureAndCaptureRollback(t *testing.T) {
	n, sockets := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, n, sockets)
	one.stackFactory = func(context.Context, Device, CoreConfig, *flowHandler, chan<- error) (packetStack, error) {
		var pointer *singStack
		return pointer, errors.New("injected stack creation failure")
	}
	require.ErrorContains(t, one.Run(context.Background()), "stack creation failure")
	assertReleased(t, n, sockets)
	n, sockets = newMemoryNetwork(), &loopSockets{}
	one = lifecycleEngine(t, n, sockets)
	one.stackFactory = func(context.Context, Device, CoreConfig, *flowHandler, chan<- error) (packetStack, error) {
		return nil, nil
	}
	require.ErrorContains(t, one.Run(context.Background()), "nil stack")
	assertReleased(t, n, sockets)
	n, sockets = newMemoryNetwork(), &loopSockets{}
	one = lifecycleEngine(t, n, sockets)
	cfg := one.policy.Load().cfg
	cfg.Core.AutoRoute = true
	cfg.Core.OutboundInterface = "test-uplink"
	cancel, done := runReady(t, one)
	cancel()
	require.NoError(t, waitRun(t, done))
	require.Contains(t, n.events, "add 0.0.0.0/1")
	require.Contains(t, n.events, "add 128.0.0.0/1")
	assertReleased(t, n, sockets)
	require.Equal(t, "delete 128.0.0.0/1", n.events[len(n.events)-3])
	require.Equal(t, "delete 0.0.0.0/1", n.events[len(n.events)-2])
}

func TestGatewayConfigValidation(t *testing.T) {
	cleanProxyEnv(t)
	for _, extra := range []string{"stack='unknown'", "auto-route=true", "outbound-interface='bad\nname'", "tun='same'\noutbound-interface='same'", "network='10.192.0.254/24'"} {
		_, err := ParseConfig([]byte(baseConfig + extra))
		require.Error(t, err)
	}
	_, err := ParseConfig([]byte(baseConfig + "[[rules]]\ntype='IP-CIDR'\npattern='0.0.0.0/0'\noutbound='reject'"))
	require.ErrorContains(t, err, "outbound-interface")
	one := testEngine(t)
	reserved := netip.MustParseAddr(one.ip.String()).Next()
	for i := 0; i < 100; i++ {
		record := one.dnsTable.Set(string(rune('a'+i))+".example", "A")
		require.NotEqual(t, reserved.String(), record.IP.String())
	}
}

func TestPacketTraceContainsHeadersOnly(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 6
	copy(packet[12:16], []byte{192, 0, 2, 2})
	copy(packet[16:20], []byte{198, 51, 100, 1})
	packet[23] = 80
	packet[33] = 2
	packet = append(packet, []byte("private-payload-password")...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	framed := append(make([]byte, singtun.PacketOffset), packet...)
	tracePacket(context.Background(), "read", framed)
	require.Contains(t, output.String(), "192.0.2.2")
	require.Contains(t, output.String(), "destination_port")
	require.Contains(t, output.String(), "tcp_checksum_valid")
	require.NotContains(t, output.String(), "private-payload-password")
	tracePacket(context.Background(), "write", nil)
	tracePacket(context.Background(), "write", []byte{0x60})
}

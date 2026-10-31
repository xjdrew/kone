package kone

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	singtun "github.com/sagernet/sing-tun"
)

type packetStack interface {
	Start() error
	Close() error
}
type stackFactory func(context.Context, Device, CoreConfig, *flowHandler, chan<- error) (packetStack, error)

// Only the basic Tun interface is exposed to the stack: all packet reads pass
// through this boundary, including mixed-stack reads, so terminal failures
// cannot silently leave a process running with a dead tunnel.
type supervisedTun struct {
	singtun.Tun
	ctx     context.Context
	fail    chan<- error
	mu      sync.Mutex
	closed  bool
	ioTasks sync.WaitGroup
	writeMu sync.Mutex
}

func (t *supervisedTun) report(err error) {
	if err != nil && t.ctx.Err() == nil && !singtun.IsRecoverableReadError(err) {
		select {
		case t.fail <- fmt.Errorf("TUN I/O: %w", err):
		default:
		}
	}
}
func (t *supervisedTun) beginIO() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.ioTasks.Add(1)
	return true
}
func (t *supervisedTun) Read(p []byte) (int, error) {
	if !t.beginIO() {
		return 0, net.ErrClosed
	}
	defer t.ioTasks.Done()
	n, err := t.Tun.Read(p)
	t.report(err)
	return n, err
}
func (t *supervisedTun) wait() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.ioTasks.Wait()
}
func (t *supervisedTun) Write(p []byte) (int, error) {
	if !t.beginIO() {
		return 0, net.ErrClosed
	}
	defer t.ioTasks.Done()
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	n, err := t.Tun.Write(p)
	t.report(err)
	return n, err
}

type singStack struct {
	packetStack
	io   *supervisedTun
	once sync.Once
	err  error
}

func (s *singStack) Wait() { s.io.wait() }

func (s *singStack) Close() error {
	s.once.Do(func() {
		s.io.mu.Lock()
		s.io.closed = true
		s.io.mu.Unlock()
		s.err = s.packetStack.Close()
	})
	return s.err
}
func newSingStack(ctx context.Context, device Device, cfg CoreConfig, handler *flowHandler, fail chan<- error) (packetStack, error) {
	d, ok := device.(*singDevice)
	if !ok {
		return nil, errors.New("device does not expose a sing-tun interface")
	}
	options := deviceOptions(cfg)
	options.Name = d.Name()
	io := &supervisedTun{Tun: d.Tun, ctx: ctx, fail: fail}
	t, err := stackTun(io, cfg.Stack)
	if err != nil {
		return nil, err
	}
	stack, err := singtun.NewStack(cfg.Stack, singtun.StackOptions{
		Context: ctx, Tun: t, TunOptions: options, Handler: handler, Logger: stackLogger{fail: fail},
		UDPTimeout: 2 * time.Minute, ICMPTimeout: time.Minute, UDPNATMax: 4096,
		UDPMapping:   singtun.NATMappingAddressAndPortDependent,
		UDPFiltering: singtun.NATFilteringAddressAndPortDependent,
	})
	if err != nil {
		return nil, err
	}
	return &singStack{packetStack: stack, io: io}, nil
}

// Fatal/Panic from a dependency are engine failures, never process-wide exits.
type stackLogger struct{ fail chan<- error }

func (l stackLogger) Trace(args ...any) { slog.Debug("sing-tun", "detail", fmt.Sprint(args...)) }
func (l stackLogger) Debug(args ...any) { slog.Debug("sing-tun", "detail", fmt.Sprint(args...)) }
func (l stackLogger) Info(args ...any)  { slog.Info("sing-tun", "detail", fmt.Sprint(args...)) }
func (l stackLogger) Warn(args ...any)  { slog.Warn("sing-tun", "detail", fmt.Sprint(args...)) }
func (l stackLogger) Error(args ...any) { slog.Error("sing-tun", "detail", fmt.Sprint(args...)) }
func (l stackLogger) Fatal(args ...any) {
	err := fmt.Errorf("sing-tun: %s", fmt.Sprint(args...))
	select {
	case l.fail <- err:
	default:
	}
	slog.Error("sing-tun failed", "error", err)
}
func (l stackLogger) Panic(args ...any) { l.Fatal(args...) }

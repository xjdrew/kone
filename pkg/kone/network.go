package kone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"reflect"
	"time"
)

// Device is the packet interface owned by one engine run.
type Device interface {
	io.ReadWriteCloser
	Name() string
}

// Interfaces holding a nil pointer are non-nil. Keep failed opens out of the
// owned-resource set so cleanup never calls a promoted method on a nil receiver.
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// Cleanup restores a successful network change. A non-nil cleanup returned
// alongside an error must also be called to undo partially completed setup.
type Cleanup func(context.Context) error

// Network separates privileged OS operations from engine lifecycle management.
// Implementations must honor cancellation and preserve pre-existing settings.
type Network interface {
	Open(context.Context, CoreConfig) (Device, error)
	Configure(context.Context, Device, CoreConfig) (Cleanup, error)
	AddRoute(context.Context, Device, *net.IPNet) (Cleanup, error)
}

type undoStack struct{ actions []namedUndo }
type namedUndo struct {
	name string
	undo Cleanup
}

func (s *undoStack) add(name string, undo Cleanup) {
	if undo != nil {
		s.actions = append(s.actions, namedUndo{name, undo})
	}
}
func (s *undoStack) restore(ctx context.Context) error {
	var errs []error
	for i := len(s.actions) - 1; i >= 0; i-- {
		if err := s.actions[i].undo(ctx); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", s.actions[i].name, err))
		}
	}
	s.actions = nil
	return errors.Join(errs...)
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)
type systemNetwork struct {
	run     commandRunner
	gateway string
}

// Sockets allows the same lifecycle to run in a different network namespace or
// in unprivileged end-to-end tests. net.ListenConfig implements this interface.
type Sockets interface {
	Listen(context.Context, string, string) (net.Listener, error)
	ListenPacket(context.Context, string, string) (net.PacketConn, error)
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	slog.Debug("Executing network command", "command", name)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", name, ctx.Err())
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, &stderr)
	}
	return out, nil
}

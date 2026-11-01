package desktop

import (
	"context"
	"errors"
	"net/rpc"
	"strings"
	"time"
)

type RecoverDNSRequest struct {
	ID       string
	Deadline time.Time
}

func validDNSRecoveryID(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

// A recovery-only helper accepts exactly one mutation and can never start
// capture before or after it. The core rechecks lease ownership under its lock.
func (s *helperService) RecoverDNS(request RecoverDNSRequest, _ *Empty) error {
	if !validDNSRecoveryID(request.ID) {
		return errors.New("invalid system DNS recovery identity")
	}
	if request.Deadline.IsZero() || !request.Deadline.After(time.Now()) {
		return context.DeadlineExceeded
	}
	s.mu.Lock()
	if s.started || s.engine != nil {
		s.mu.Unlock()
		return errors.New("DNS recovery requires a fresh helper without a capture engine")
	}
	s.started = true
	recoverDNS := s.recoverDNS
	s.mu.Unlock()
	if recoverDNS == nil {
		return errors.New("system DNS recovery is unavailable")
	}
	deadline := time.Now().Add(20 * time.Second)
	if request.Deadline.Before(deadline) {
		deadline = request.Deadline
	}
	ctx, cancel := context.WithDeadline(s.ctx, deadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := recoverDNS(ctx, request.ID); err != nil {
		return errors.New(helperError(err))
	}
	return ctx.Err()
}

type recoveryCallbacks struct{}

func (*recoveryCallbacks) Logs(batch LogBatch, _ *Empty) error {
	if len(batch.Data) > maxLogBatchBytes {
		return errors.New("helper recovery log batch exceeds bound")
	}
	return nil
}

func recoverDNSWithConnector(parent context.Context, id string, connect Connector) error {
	if !validDNSRecoveryID(id) {
		return errors.New("invalid system DNS recovery identity")
	}
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if connect == nil {
		return errors.New("system DNS recovery helper transport is unavailable")
	}
	commands, events, err := connect(ctx)
	if commands != nil {
		defer commands.Close()
	}
	if events != nil {
		defer events.Close()
	}
	if err != nil {
		return err
	}
	if commands == nil || events == nil {
		return errors.New("system DNS recovery helper transport is incomplete")
	}
	client := rpc.NewClient(commands)
	defer client.Close()
	callbacks := rpc.NewServer()
	if err := callbacks.RegisterName("Callbacks", &recoveryCallbacks{}); err != nil {
		return err
	}
	callbackDone := make(chan struct{})
	go func() { defer close(callbackDone); callbacks.ServeConn(events) }()
	defer func() { events.Close(); <-callbackDone }()
	deadline := time.Now().Add(20 * time.Second)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	var reply Empty
	call := client.Go("Network.RecoverDNS", RecoverDNSRequest{ID: id, Deadline: deadline}, &reply, make(chan *rpc.Call, 1))
	select {
	case result := <-call.Done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return result.Error
	case <-ctx.Done():
		return ctx.Err()
	}
}

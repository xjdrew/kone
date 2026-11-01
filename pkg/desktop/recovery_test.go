package desktop

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestDNSRecoveryHelperIsSingleUseAndNeverStartsCapture(t *testing.T) {
	id := strings.Repeat("a", 32)
	var calls atomic.Int32
	s := &helperService{ctx: t.Context(), recoverDNS: func(ctx context.Context, got string) error {
		calls.Add(1)
		require.Equal(t, id, got)
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), 20*time.Second)
		return nil
	}}
	request := RecoverDNSRequest{ID: id, Deadline: time.Now().Add(time.Minute)}
	require.NoError(t, s.RecoverDNS(request, &Empty{}))
	require.Equal(t, int32(1), calls.Load())
	require.Nil(t, s.engine)
	require.Error(t, s.RecoverDNS(request, &Empty{}))
	require.Error(t, s.Start(StartRequest{}, &Empty{}))
	for _, id := range []string{"", strings.Repeat("a", 31), strings.Repeat("A", 32), "../" + strings.Repeat("a", 29)} {
		require.Error(t, (&helperService{}).RecoverDNS(RecoverDNSRequest{ID: id, Deadline: time.Now().Add(time.Second)}, &Empty{}))
	}
	require.ErrorIs(t, (&helperService{}).RecoverDNS(RecoverDNSRequest{ID: request.ID}, &Empty{}), context.DeadlineExceeded)
	require.Error(t, (&helperService{started: true}).RecoverDNS(request, &Empty{}))
	require.Error(t, (&helperService{ctx: t.Context()}).RecoverDNS(request, &Empty{}))
}

func TestDNSRecoveryIPCClosesBothStreamsAndCancelsWithoutAnEngine(t *testing.T) {
	for _, mode := range []string{"success", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			commandsParent, commandsHelper := net.Pipe()
			eventsParent, eventsHelper := net.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered := make(chan struct{})
			finished := make(chan error, 1)
			go func() {
				finished <- serveHelper(t.Context(), commandsHelper, eventsHelper, func(*kone.KoneConfig) (NetworkEngine, error) {
					t.Error("recovery must never construct a capture engine")
					return nil, errors.New("unexpected engine")
				}, func(ctx context.Context, _ string) error {
					close(entered)
					if mode == "cancel" {
						<-ctx.Done()
						return ctx.Err()
					}
					if mode == "error" {
						return errors.New("owned lease changed")
					}
					return nil
				})
			}()
			if mode == "cancel" {
				go func() { <-entered; cancel() }()
			}
			err := recoverDNSWithConnector(ctx, strings.Repeat("a", 32), func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
				return commandsParent, eventsParent, nil
			})
			if mode == "success" {
				require.NoError(t, err)
			} else if mode == "cancel" {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorContains(t, err, "owned lease changed")
			}
			select {
			case err := <-finished:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("recovery helper did not exit after parent closed IPC")
			}
		})
	}
}

func TestDNSRecoveryValidatesBeforeConnectingAndPreservesLauncherErrors(t *testing.T) {
	connect := func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		t.Error("must not authorize helper")
		return nil, nil, nil
	}
	require.Error(t, recoverDNSWithConnector(t.Context(), "bad", connect))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, recoverDNSWithConnector(ctx, strings.Repeat("a", 32), connect), context.Canceled)
	require.Error(t, recoverDNSWithConnector(t.Context(), strings.Repeat("a", 32), nil))
	denied := errors.New("UAC denied")
	require.ErrorIs(t, recoverDNSWithConnector(t.Context(), strings.Repeat("a", 32), func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) { return nil, nil, denied }), denied)
	require.Error(t, recoverDNSWithConnector(t.Context(), strings.Repeat("a", 32), func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) { return nil, nil, nil }))
	require.Error(t, (&recoveryCallbacks{}).Logs(LogBatch{Data: make([]byte, maxLogBatchBytes+1)}, &Empty{}))
}

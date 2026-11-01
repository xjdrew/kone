package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/rpc"
	"sync"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

const maxLogBatchBytes = 256 << 10

type HelperLogging struct {
	Store     *logstore.Store
	Configure func(kone.GeneralConfig) error
}
type LogBatch struct {
	Data    []byte
	Cursor  uint64
	Dropped uint64
}
type helperLogForwarder struct {
	mu              sync.Mutex
	store           *logstore.Store
	client          *rpc.Client
	cursor, dropped uint64
	pending         *pendingLogCall
	degraded        bool
}
type pendingLogCall struct {
	result          chan error
	cursor, dropped uint64
	hasMore         bool
}

func serveProductionHelper(ctx context.Context, commands, events io.ReadWriteCloser, factory EngineFactory) error {
	if factory != nil {
		return ServeHelper(ctx, commands, events, factory)
	}
	store := logstore.New()
	previous := slog.Default()
	defer slog.SetDefault(previous)
	configure := func(cfg kone.GeneralConfig) error {
		next, err := kone.NewLoggingHandler(io.Discard, cfg, false)
		if err != nil {
			return err
		}
		slog.SetDefault(slog.New(store.Handler(next, "helper")).With("service", "kone"))
		return nil
	}
	if err := configure(kone.DefaultConfig().General); err != nil {
		return err
	}
	return ServeHelper(ctx, commands, events, nil, HelperLogging{Store: store, Configure: configure})
}

func (f *helperLogForwarder) flush(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for range 128 { // The complete retained history is at most 1000 records.
		if err := ctx.Err(); err != nil {
			f.degraded = true
			return err
		}
		if f.pending == nil {
			page, err := f.store.Query(logstore.Query{After: f.cursor, Limit: 8})
			if err != nil {
				return err
			}
			if page.NextCursor == f.cursor {
				return nil
			}
			dropped := f.dropped
			if page.OldestCursor > f.cursor+1 {
				dropped += page.OldestCursor - f.cursor - 1
			}
			data, err := json.Marshal(page.Records)
			if err != nil || len(data) > maxLogBatchBytes {
				f.degraded = true
				return errors.New("helper log batch exceeds bound")
			}
			pending := &pendingLogCall{result: make(chan error, 1), cursor: page.NextCursor, dropped: dropped, hasMore: page.HasMore}
			f.pending = pending
			go func() {
				var reply Empty
				pending.result <- f.client.Call("Callbacks.Logs", LogBatch{Data: data, Cursor: pending.cursor, Dropped: pending.dropped}, &reply)
			}()
		}
		pending := f.pending
		select {
		case err := <-pending.result:
			f.pending = nil
			if err != nil {
				f.degraded = true
				return err
			}
			f.degraded = false
		case <-ctx.Done():
			// Logs are best effort. Keep at most one pending call and leave the
			// shared Device/Finished channel open; lifecycle shutdown closes it.
			f.degraded = true
			return ctx.Err()
		}
		f.cursor = pending.cursor
		f.dropped = pending.dropped
		if !pending.hasMore {
			return nil
		}
	}
	return nil
}
func (s *helperService) logsDegraded() bool {
	if s.logForwarder == nil {
		return false
	}
	s.logForwarder.mu.Lock()
	defer s.logForwarder.mu.Unlock()
	return s.logForwarder.degraded || s.logForwarder.pending != nil
}
func (s *helperService) flushLogs() {
	if s.logForwarder == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	_ = s.logForwarder.flush(ctx)
}
func (s *helperService) logFailure(message string, err error) {
	if err != nil {
		s.logEvent(slog.LevelError, message, slog.String("error", err.Error()))
	}
	s.flushLogs()
}

func (s *helperService) logEvent(level slog.Level, message string, attrs ...slog.Attr) {
	if s.logForwarder != nil {
		slog.New(s.logForwarder.store.Handler(nil, "helper")).With("service", "kone").LogAttrs(context.Background(), level, message, attrs...)
	}
}

func (e *RemoteEngine) logEvent(level slog.Level, message string, attrs ...slog.Attr) {
	e.mu.Lock()
	local, sink := e.logs, e.logSink
	e.mu.Unlock()
	slog.New(local.Handler(nil, "helper")).With("service", "kone").LogAttrs(context.Background(), level, message, attrs...)
	if sink != nil && sink != local {
		slog.New(sink.Handler(nil, "helper")).With("service", "kone").LogAttrs(context.Background(), level, message, attrs...)
	}
}
func (s *helperService) pumpLogs(ctx context.Context) {
	if s.logForwarder == nil {
		return
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.flushLogs()
		case <-s.logForwarder.store.Changed():
			s.flushLogs()
		}
	}
}

func (e *RemoteEngine) SetLogStore(store *logstore.Store) error {
	if store == nil {
		return errors.New("runtime log store is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started || e.closed {
		return errors.New("runtime log sink must be set before Run")
	}
	e.logSink = store
	return nil
}
func (e *RemoteEngine) LogStatus() logstore.RemoteStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.logStatus
}
func (e *RemoteEngine) Logs(query logstore.Query) (logstore.Page, error) { return e.logs.Query(query) }

func (c *callbacks) Logs(batch LogBatch, _ *Empty) error {
	if len(batch.Data) > maxLogBatchBytes {
		return errors.New("helper log payload exceeds bound")
	}
	var records []logstore.Record
	decoder := json.NewDecoder(bytes.NewReader(batch.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&records) != nil || len(records) > 8 {
		return errors.New("invalid helper log batch")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid helper log batch framing")
	}
	e := c.engine
	e.mu.Lock()
	last := e.logCursor
	if batch.Cursor <= last {
		e.mu.Unlock()
		return nil
	}
	for _, record := range records {
		if record.ID <= last || record.ID > batch.Cursor {
			e.mu.Unlock()
			return errors.New("invalid helper log record cursor")
		}
		last = record.ID
	}
	e.logCursor = batch.Cursor
	e.logStatus.Dropped = batch.Dropped
	sink, local := e.logSink, e.logs
	e.mu.Unlock()
	for _, record := range records {
		record.Source = "helper"
		local.Append(record)
		if sink != nil && sink != local {
			sink.Append(record)
		}
	}
	return nil
}

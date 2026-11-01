package desktop

import (
	"context"
	"net/rpc"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

const maxProbeProgressUpdates = 8

type ProbeProgressEvent struct {
	ID       string
	Sequence uint64
	Result   kone.DiagnosticResult
}

type helperProbeProgress struct {
	mu       sync.Mutex
	client   *rpc.Client
	id       string
	sequence uint64
	pending  chan error
	slots    chan struct{}
	disabled bool
}

// One pending call per bounded diagnostic is enough. A slow/older callback
// receiver may lose intermediate progress, but cannot stall the actual probe,
// multiply goroutines, close the events channel or interrupt business capture.
func (progress *helperProbeProgress) publish(ctx context.Context, result kone.DiagnosticResult) {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if progress.disabled || progress.sequence >= maxProbeProgressUpdates || ctx.Err() != nil || progress.slots == nil {
		return
	}
	if progress.pending != nil {
		select {
		case err := <-progress.pending:
			progress.pending = nil
			if err != nil {
				progress.disabled = true
				return
			}
		default:
			return
		}
	}
	select {
	case progress.slots <- struct{}{}:
	default:
		return
	}
	progress.sequence++
	event := ProbeProgressEvent{ID: progress.id, Sequence: progress.sequence, Result: safeProbeProgress(result)}
	done := make(chan error, 1)
	progress.pending = done
	go func() {
		defer func() { <-progress.slots }()
		var reply Empty
		done <- progress.client.Call("Callbacks.ProbeProgress", event, &reply)
	}()
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		progress.pending = nil
		progress.disabled = err != nil
	case <-ctx.Done():
	case <-timer.C:
	}
}

type remoteProbeProgress struct {
	delivery sync.Mutex
	ctx      context.Context
	active   atomic.Bool
	sequence uint64 // Protected by RemoteEngine.mu.
}

func (receiver *callbacks) ProbeProgress(event ProbeProgressEvent, _ *Empty) error {
	if event.ID == "" || len(event.ID) > 64 || event.Sequence == 0 || event.Sequence > maxProbeProgressUpdates {
		return nil
	}
	engine := receiver.engine
	engine.mu.Lock()
	observer := engine.probeObservers[event.ID]
	engine.mu.Unlock()
	if observer == nil {
		return nil
	}
	observer.delivery.Lock()
	defer observer.delivery.Unlock()
	engine.mu.Lock()
	if engine.closed || observer == nil || event.Sequence <= observer.sequence || !observer.active.Load() || observer.ctx.Err() != nil {
		engine.mu.Unlock()
		return nil
	}
	observer.sequence = event.Sequence
	engine.mu.Unlock()
	if observer.active.Load() && observer.ctx.Err() == nil {
		kone.ReportDiagnosticProgress(observer.ctx, safeProbeProgress(event.Result))
	}
	return nil
}

// Rebuild a small value snapshot. Never forward arbitrary helper fields,
// configuration, URLs with userinfo, mutable pointers, maps or slices.
func safeProbeProgress(input kone.DiagnosticResult) kone.DiagnosticResult {
	result := kone.DiagnosticResult{Stage: input.Stage, Status: input.Status, Host: input.Host, Protocols: input.Protocols, Progress: input.Progress, ConfigVersion: input.ConfigVersion}
	if input.Protocol == "tcp" || input.Protocol == "udp" {
		result.Protocol = input.Protocol
	}
	safe := func(text string) string { return logstore.RedactText(text) }
	result.Stage, result.Status = safe(result.Stage), safe(result.Status)
	if result.Host.Address != "" && kone.ValidateDiagnosticTarget(result.Host.Address) != nil {
		result.Host.Address = ""
	}
	result.Host.Status, result.Host.Message = safe(result.Host.Status), safe(result.Host.Message)
	for _, check := range []*kone.DiagnosticCheck{&result.Protocols.TCP, &result.Protocols.TLS, &result.Protocols.UDP} {
		check.Status, check.Message, check.Evidence = safe(check.Status), safe(check.Message), safe(check.Evidence)
	}
	if input.ConnectLatencyMS != nil && *input.ConnectLatencyMS >= 0 || input.ConnectLatencyMS == nil && input.ConnectLatencyMeasured {
		latency := int64(0)
		if input.ConnectLatencyMS != nil {
			latency = *input.ConnectLatencyMS
		}
		result.ConnectLatencyMS = &latency
		result.ConnectLatencyMeasured = true
	}
	if result.Progress.Total < 0 || result.Progress.Total > 8 || result.Progress.Completed < 0 || result.Progress.Completed > result.Progress.Total {
		result.Progress = kone.DiagnosticProgress{}
	}
	result.Progress.Stage = safe(result.Progress.Stage)
	return result
}

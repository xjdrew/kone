package kone

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/xjdrew/kone/pkg/logstore"
)

func reportableFlowError(err error, stage string) bool {
	if err == nil || errors.Is(err, ErrRejected) || errors.Is(err, ErrUDPUnsupported) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return false
	}
	return stage != "transfer" || !errors.Is(err, io.EOF)
}

func (h *flowHandler) logFlowFailure(ctx context.Context, snapshot *runtimeSnapshot, protocol, outbound, target, stage string, err error) {
	if !reportableFlowError(err, stage) || h.stopping(ctx) {
		return
	}
	if typed := DiagnosticStage(err); typed != "" {
		stage = typed
	}
	message := logstore.RedactText(diagnosticMessage(err, snapshot.cfg))
	slog.ErrorContext(ctx, "Outbound flow failed", "protocol", protocol, "outbound", outbound, "stage", stage, "target", target, "config_version", snapshot.configurationVersion(), "error", message)
}

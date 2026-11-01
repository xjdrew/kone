package kone

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/logstore"
)

func TestLoggingHandlerCompositionKeepsHistoryAndExistingDefault(t *testing.T) {
	previous := slog.Default()
	store := logstore.New()
	cfg := DefaultConfig().General
	first, err := NewLoggingHandler(io.Discard, cfg, false)
	require.NoError(t, err)
	slog.New(store.Handler(first, "management")).Info("before reconfiguration")
	cfg.LogLevel = "error"
	cfg.LogFormat = "json"
	next, err := NewLoggingHandler(io.Discard, cfg, false)
	require.NoError(t, err)
	logger := slog.New(store.Handler(next, "management"))
	logger.Info("excluded by new level")
	logger.Error("after reconfiguration")
	history, err := store.Query(logstore.Query{})
	require.NoError(t, err)
	require.Len(t, history.Records, 2)
	require.Equal(t, "before reconfiguration", history.Records[0].Message)
	require.Equal(t, "after reconfiguration", history.Records[1].Message)
	require.Same(t, previous, slog.Default())
	debug, err := NewLoggingHandler(io.Discard, cfg, true)
	require.NoError(t, err)
	require.True(t, debug.Enabled(t.Context(), slog.LevelDebug))
	cfg.LogLevel = "unknown"
	_, err = NewLoggingHandler(io.Discard, cfg, false)
	require.Error(t, err)
	cfg.LogLevel = "info"
	cfg.LogFormat = "unknown"
	_, err = NewLoggingHandler(io.Discard, cfg, false)
	require.Error(t, err)
	require.Same(t, previous, slog.Default())
}

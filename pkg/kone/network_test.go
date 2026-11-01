package kone

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/logstore"
)

func TestCommandIOHelper(t *testing.T) {
	mode := os.Getenv("KONE_COMMAND_TEST_HELPER")
	if mode == "" {
		return
	}
	if mode == "wait" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	fmt.Fprint(os.Stdout, `{"value":42}`)
	fmt.Fprint(os.Stderr, "progress output must not corrupt JSON")
	os.Exit(0)
}

func TestCommandOutputAndCancellation(t *testing.T) {
	store := logstore.New()
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(store.Handler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}), "helper")))
	t.Setenv("KONE_COMMAND_TEST_HELPER", "output")
	for range 3 {
		output, err := runCommand(context.Background(), os.Args[0], "-test.run=^TestCommandIOHelper$")
		require.NoError(t, err)
		require.JSONEq(t, `{"value":42}`, string(output))
	}
	t.Setenv("KONE_COMMAND_TEST_HELPER", "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := runCommand(ctx, os.Args[0], "-test.run=^TestCommandIOHelper$")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	logs, err := store.Query(logstore.Query{})
	require.NoError(t, err)
	require.Empty(t, logs.Records, "periodic command execution is not a state-change event, even at DEBUG")
}

package kone

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
	t.Setenv("KONE_COMMAND_TEST_HELPER", "output")
	output, err := runCommand(context.Background(), os.Args[0], "-test.run=^TestCommandIOHelper$")
	require.NoError(t, err)
	require.JSONEq(t, `{"value":42}`, string(output))
	t.Setenv("KONE_COMMAND_TEST_HELPER", "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = runCommand(ctx, os.Args[0], "-test.run=^TestCommandIOHelper$")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

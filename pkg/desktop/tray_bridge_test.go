package desktop

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func fakeTrayProcess(t *testing.T) (trayProcess, *io.PipeWriter, <-chan trayStatus) {
	t.Helper()
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	states := make(chan trayStatus, 8)
	exited := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { inputReader.Close(); outputWriter.Close(); close(exited) }) }
	go func() {
		defer finish()
		decoder := json.NewDecoder(inputReader)
		for {
			var status trayStatus
			if err := decoder.Decode(&status); err != nil {
				return
			}
			select {
			case states <- status:
			case <-exited:
				return
			}
		}
	}()
	t.Cleanup(func() { finish(); inputWriter.Close(); outputReader.Close() })
	return trayProcess{input: inputWriter, output: outputReader, wait: func() error { <-exited; return nil }, kill: func() error { finish(); return nil }}, outputWriter, states
}

func TestNativeTrayBridgeUsesOnlyLifecycleFactsAndFixedActions(t *testing.T) {
	process, output, states := fakeTrayProcess(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var state atomic.Value
	state.Store("running")
	actions := make(chan uintptr, 5)
	callbacks := TrayActions{State: func() string { return state.Load().(string) }, Open: func() { actions <- 1 }, Pause: func() { actions <- 2 }, Exit: func() { actions <- 3; cancel() }, Start: func() { actions <- 4 }, Diagnostics: func() { actions <- 5 }}
	done := make(chan error, 1)
	go func() { done <- runTrayBridge(ctx, callbacks, process, time.Second) }()
	_, err := io.WriteString(output, "READY\n")
	require.NoError(t, err)
	initial := <-states
	require.Equal(t, "running", initial.Status)
	require.True(t, initial.CanPause)
	require.False(t, initial.CanStart)
	state.Store("paused")
	select {
	case next := <-states:
		require.Equal(t, "paused", next.Status)
		require.True(t, next.CanStart)
		require.False(t, next.CanPause)
	case <-time.After(2 * time.Second):
		t.Fatal("tray did not receive the controller's updated lifecycle state")
	}
	for _, action := range []struct {
		text string
		id   uintptr
	}{{"OPEN", 1}, {"START", 4}, {"PAUSE", 2}, {"DIAGNOSTICS", 5}, {"EXIT", 3}} {
		_, err = io.WriteString(output, action.text+"\n")
		require.NoError(t, err)
		select {
		case id := <-actions:
			require.Equal(t, action.id, id)
		case <-time.After(time.Second):
			t.Fatal("native action was not dispatched")
		}
	}
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("native helper did not exit when the parent canceled")
	}
}

func TestNativeTrayBridgeRejectsEarlyUnknownAndOversizedMessages(t *testing.T) {
	for _, input := range []string{"OPEN\n", "READY\nUNTRUSTED_COMMAND\n", "READY\n" + strings.Repeat("x", 300) + "\n", "READY\nREADY\n"} {
		t.Run(input[:4], func(t *testing.T) {
			process, output, _ := fakeTrayProcess(t)
			var calls atomic.Int32
			done := make(chan error, 1)
			go func() {
				done <- runTrayBridge(context.Background(), TrayActions{Open: func() { calls.Add(1) }}, process, time.Second)
			}()
			go func() { io.WriteString(output, input) }()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(3 * time.Second):
				t.Fatal("invalid native protocol did not stop the helper")
			}
			require.Zero(t, calls.Load(), "unexpected native output cannot invoke controller actions")
		})
	}
}

func TestNativeTrayReadinessTimeoutAndCancellationAreBounded(t *testing.T) {
	process, _, _ := fakeTrayProcess(t)
	require.ErrorContains(t, runTrayBridge(context.Background(), TrayActions{}, process, 20*time.Millisecond), "ready")
	process, _, _ = fakeTrayProcess(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, runTrayBridge(ctx, TrayActions{}, process, time.Second))
	require.Equal(t, "unknown", nativeTrayStatus(TrayActions{}).Status)
	status := nativeTrayStatus(TrayActions{State: func() string { return strings.Repeat("x", 200) + "\n" }})
	require.LessOrEqual(t, len(status.Status), 128)
	require.NotContains(t, status.Status, "\n")
}

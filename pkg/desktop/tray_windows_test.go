package desktop

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWindowsHiddenTrayMessagePumpStateRestartAndExit(t *testing.T) {
	// Run the real hidden window and Win32 message pump. Replace only Explorer's
	// notification transport so this also works in a CI service session; no
	// visible menu/icon, UAC, network helper or host network change is created.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var state atomic.Value
	state.Store("running")
	var adds, deletes, exits atomic.Int32
	created := make(chan uintptr, 1)
	tips := make(chan string, 8)
	actions := TrayActions{State: func() string { return state.Load().(string) }, Exit: func() { exits.Add(1); cancel() }}
	notify := func(operation uintptr, data *trayIconData) (uintptr, error) {
		switch operation {
		case 0:
			if adds.Add(1) == 1 {
				created <- data.Window
			}
		case 1:
			select {
			case tips <- windows.UTF16ToString(data.Tip[:]):
			default:
			}
		case 2:
			deletes.Add(1)
		}
		return 1, nil
	}
	done := make(chan error, 1)
	go func() { done <- runTray(ctx, actions, notify) }()
	var hwnd uintptr
	select {
	case hwnd = <-created:
	case err := <-done:
		t.Fatalf("hidden window startup failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("hidden window was not created")
	}
	state.Store("paused")
	trayUser32.NewProc("PostMessageW").Call(hwnd, 0x0113, 1, 0)
	select {
	case tip := <-tips:
		require.Contains(t, tip, "paused")
	case <-time.After(time.Second):
		t.Fatal("tooltip did not reflect the actual controller state")
	}
	message, _, _ := trayUser32.NewProc("RegisterWindowMessageW").Call(uintptr(unsafe.Pointer(trayUTF16("TaskbarCreated"))))
	trayUser32.NewProc("PostMessageW").Call(hwnd, message, 0, 0)
	require.Eventually(t, func() bool { return adds.Load() == 2 }, time.Second, time.Millisecond, "Explorer restart must re-register the owned tray icon")
	trayUser32.NewProc("PostMessageW").Call(hwnd, 0x0016, 1, 0)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("tray exit did not stop its message pump")
	}
	require.Equal(t, int32(1), exits.Load())
	require.Equal(t, int32(1), deletes.Load())
	isWindow, _, _ := trayUser32.NewProc("IsWindow").Call(hwnd)
	require.Zero(t, isWindow, "the owned hidden window must be destroyed")
}

func TestWindowsExplorerTrayRegistrationAndCleanup(t *testing.T) {
	window, _, _ := trayUser32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(trayUTF16("Shell_TrayWnd"))), 0)
	if window == 0 {
		t.Skip("Explorer notification area is unavailable in this Windows session")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	created := make(chan struct{}, 1)
	notify := func(operation uintptr, data *trayIconData) (uintptr, error) {
		result, err := nativeTrayNotify(operation, data)
		if operation == 0 && result != 0 {
			created <- struct{}{}
		}
		return result, err
	}
	done := make(chan error, 1)
	go func() { done <- runTray(ctx, TrayActions{State: func() string { return "paused" }}, notify) }()
	select {
	case <-created:
	case err := <-done:
		require.NoError(t, err)
		return
	case <-time.After(3 * time.Second):
		t.Fatal("Explorer tray registration timed out")
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("owned Explorer tray icon did not clean up")
	}
}

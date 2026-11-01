package integration

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
	"golang.org/x/sys/windows"
)

func TestWindowsStyledTrayRetainsOpenAndShutdownActions(t *testing.T) {
	// Run the native tray and message pump with isolated callbacks. No browser,
	// helper, user profile or networking operation is launched by these actions.
	user32 := windows.NewLazySystemDLL("user32.dll")
	shellClass, err := windows.UTF16PtrFromString("Shell_TrayWnd")
	require.NoError(t, err)
	explorer, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(shellClass)), 0)
	if explorer == 0 {
		t.Skip("Explorer notification area is unavailable in this Windows session")
	}
	class, err := windows.UTF16PtrFromString("KoneManagementTray")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var stateReads, opened, exited atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- desktop.RunTray(ctx, desktop.TrayActions{
			Open: func() { opened.Add(1) },
			Exit: func() { exited.Add(1); cancel() },
			State: func() string {
				stateReads.Add(1)
				return "paused"
			},
		})
	}()
	var ownedWindow uintptr
	require.Eventually(t, func() bool {
		var after uintptr
		for {
			hwnd, _, _ := user32.NewProc("FindWindowExW").Call(0, after, uintptr(unsafe.Pointer(class)), 0)
			if hwnd == 0 {
				return false
			}
			var pid uint32
			user32.NewProc("GetWindowThreadProcessId").Call(hwnd, uintptr(unsafe.Pointer(&pid)))
			if pid == uint32(os.Getpid()) && stateReads.Load() > 0 {
				ownedWindow = hwnd
				return true
			}
			after = hwnd
		}
	}, 3*time.Second, time.Millisecond)
	user32.NewProc("PostMessageW").Call(ownedWindow, 0x8001, 0, 0x0202) // Native tray left-click.
	require.Eventually(t, func() bool { return opened.Load() == 1 }, time.Second, time.Millisecond)
	user32.NewProc("PostMessageW").Call(ownedWindow, 0x0016, 1, 0) // Session shutdown uses Exit.
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("the native tray did not release its message pump")
	}
	require.Equal(t, int32(1), exited.Load())
	isWindow, _, _ := user32.NewProc("IsWindow").Call(ownedWindow)
	require.Zero(t, isWindow, "the styled tray must release its owned hidden window")
}

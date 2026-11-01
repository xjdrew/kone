package desktop

import (
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

type trayBitmap struct {
	Type, Width, Height, WidthBytes int32
	Planes, BitsPixel               uint16
	Bits                            unsafe.Pointer
}

func readTrayMenuItem(t *testing.T, menu uintptr, position uintptr) trayMenuItemInfo {
	t.Helper()
	info := trayMenuItemInfo{Size: uint32(unsafe.Sizeof(trayMenuItemInfo{})), Mask: 0x183} // MIIM_FTYPE | MIIM_BITMAP | MIIM_ID | MIIM_STATE
	got, _, _ := trayUser32.NewProc("GetMenuItemInfoW").Call(menu, position, 1, uintptr(unsafe.Pointer(&info)))
	require.NotZero(t, got)
	return info
}

func TestWindowsTrayMenuHasNativeGroupedItemsAndOwnedIcons(t *testing.T) {
	noop := func() {}
	actions := TrayActions{Open: noop, Start: noop, Pause: noop, Diagnostics: noop, Exit: noop, State: func() string { return "paused" }}
	for _, size := range []int{16, 24, 32, 48} {
		menu, err := createTrayMenu(actions, size)
		require.NoError(t, err)
		handle := menu.handle
		bitmaps := append([]uintptr(nil), menu.bitmaps...)
		count, _, _ := trayUser32.NewProc("GetMenuItemCount").Call(handle)
		require.Equal(t, uintptr(8), count)
		for position, id := range []uint32{1, 0, 4, 2, 0, 5, 0, 3} {
			info := readTrayMenuItem(t, handle, uintptr(position))
			if id == 0 {
				require.NotZero(t, info.Type&0x800, "groups use native separators")
				require.Zero(t, info.Bitmap)
				continue
			}
			require.Equal(t, id, info.ID)
			require.Zero(t, info.Type&0x100, "normal Windows menu rendering must own text and focus")
			require.NotZero(t, info.Bitmap)
			var bitmap trayBitmap
			got, _, _ := trayGDI32.NewProc("GetObjectW").Call(info.Bitmap, unsafe.Sizeof(bitmap), uintptr(unsafe.Pointer(&bitmap)))
			require.NotZero(t, got)
			require.Equal(t, int32(size), bitmap.Width)
			require.Equal(t, int32(size), bitmap.Height)
			require.Equal(t, uint16(32), bitmap.BitsPixel)
			pixels := unsafe.Slice((*uint32)(bitmap.Bits), size*size)
			visible, transparent := false, false
			for _, pixel := range pixels {
				visible = visible || pixel>>24 != 0
				transparent = transparent || pixel>>24 == 0
			}
			require.True(t, visible, "every menu action has a rendered alpha bitmap")
			require.True(t, transparent, "icons must blend into the native menu background")
		}
		defaultItem, _, _ := trayUser32.NewProc("GetMenuDefaultItem").Call(handle, 0, 0)
		require.Equal(t, uintptr(1), defaultItem)
		menu.close()
		menu.close() // Cleanup remains safe during deferred failure handling.
		isMenu, _, _ := trayUser32.NewProc("IsMenu").Call(handle)
		require.Zero(t, isMenu)
		for _, bitmap := range bitmaps {
			var object trayBitmap
			got, _, _ := trayGDI32.NewProc("GetObjectW").Call(bitmap, unsafe.Sizeof(object), uintptr(unsafe.Pointer(&object)))
			require.Zero(t, got, "closing the native menu must free each owned HBITMAP")
		}
	}
}

func TestWindowsTrayMenuLifecycleItemsReflectOneStateSnapshot(t *testing.T) {
	for _, state := range []string{"paused", "running", "starting", "degraded", "pausing", "recovery_required", "recovery_failed", "unknown"} {
		t.Run(state, func(t *testing.T) {
			reads := 0
			actions := TrayActions{Open: func() {}, Start: func() {}, Pause: func() {}, Diagnostics: func() {}, Exit: func() {}, State: func() string { reads++; return state }}
			menu, err := createTrayMenu(actions, 16)
			require.NoError(t, err)
			defer menu.close()
			require.Equal(t, 1, reads)
			start := readTrayMenuItem(t, menu.handle, 2)
			pause := readTrayMenuItem(t, menu.handle, 3)
			require.Equal(t, state != "paused", start.State&3 != 0)
			require.Equal(t, state != "running" && state != "starting" && state != "degraded", pause.State&3 != 0)
			for _, position := range []uintptr{0, 5, 7} {
				require.Zero(t, readTrayMenuItem(t, menu.handle, position).State&3)
			}
		})
	}
	menu, err := createTrayMenu(TrayActions{}, 16)
	require.NoError(t, err)
	defer menu.close()
	for _, position := range []uintptr{0, 2, 3, 5, 7} {
		require.NotZero(t, readTrayMenuItem(t, menu.handle, position).State&3, "missing callbacks stay disabled")
	}
}

func TestWindowsTrayMenuGlyphsUsePremultipliedThemeColorAtEveryScale(t *testing.T) {
	for _, size := range []int{16, 24, 32, 48} {
		for _, id := range []uintptr{2, 3, 4, 5} {
			pixels := make([]uint32, size*size)
			drawTrayMenuGlyph(pixels, size, id, 0x332211)
			antialiased := false
			for _, pixel := range pixels {
				alpha := pixel >> 24
				require.Equal(t, uint32(0x11)*alpha/255, (pixel>>16)&255)
				require.Equal(t, uint32(0x22)*alpha/255, (pixel>>8)&255)
				require.Equal(t, uint32(0x33)*alpha/255, pixel&255)
				antialiased = antialiased || alpha > 0 && alpha < 255
			}
			require.True(t, antialiased)
		}
	}
	for _, size := range []int{0, 129} {
		_, err := createTrayMenuBitmap(4, size, true)
		require.Error(t, err)
	}
	_, err := createTrayMenu(TrayActions{}, 0)
	require.Error(t, err, "construction failure must destroy its partial menu")
	require.Equal(t, 16, trayMenuIconSize(0))
}

func TestWindowsTrayMenuRechecksLifecycleAfterSelection(t *testing.T) {
	var state atomic.Value
	state.Store("paused")
	calls := make(chan uintptr, 4)
	actions := prepareTrayActions(TrayActions{State: func() string { return state.Load().(string) }, Start: func() { calls <- 4 }, Pause: func() { calls <- 2 }})
	state.Store("running")
	invokeWindowsTrayMenuAction(actions, 4)
	state.Store("paused")
	invokeWindowsTrayMenuAction(actions, 2)
	select {
	case id := <-calls:
		t.Fatalf("stale lifecycle action %d should have been ignored", id)
	default:
	}
	invokeWindowsTrayMenuAction(actions, 4)
	select {
	case id := <-calls:
		require.Equal(t, uintptr(4), id)
	case <-time.After(time.Second):
		t.Fatal("a current enabled action must still dispatch")
	}
}

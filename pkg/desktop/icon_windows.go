package desktop

import (
	"errors"
	"unsafe"

	"github.com/xjdrew/kone/web"
)

// Resource 101 is generated from the same SVG used by the Web console. Tests
// have no cmd/kone resources, so they use the embedded PNG through the same API.
func loadTrayIcon(module uintptr) (uintptr, error) {
	width, _, _ := trayUser32.NewProc("GetSystemMetrics").Call(49) // SM_CXSMICON
	height, _, _ := trayUser32.NewProc("GetSystemMetrics").Call(50)
	if width == 0 || height == 0 {
		width, height = 16, 16
	}
	icon, _, _ := trayUser32.NewProc("LoadImageW").Call(module, 101, 1, width, height, 0)
	if icon == 0 && len(web.WindowsTrayIcon) > 0 {
		icon, _, _ = trayUser32.NewProc("CreateIconFromResourceEx").Call(
			uintptr(unsafe.Pointer(&web.WindowsTrayIcon[0])), uintptr(len(web.WindowsTrayIcon)), 1, 0x30000, width, height, 0)
	}
	if icon == 0 {
		return 0, errors.New("could not load Kone notification icon")
	}
	return icon, nil
}

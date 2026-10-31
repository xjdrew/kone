package desktop

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var trayUser32 = windows.NewLazySystemDLL("user32.dll")
var trayShell32 = windows.NewLazySystemDLL("shell32.dll")
var trayWindows = struct {
	sync.Mutex
	actions map[uintptr]TrayActions
}{actions: map[uintptr]TrayActions{}}
var trayClassOnce sync.Once
var trayClassError error
var trayWindowCallback = syscall.NewCallback(trayWindowProc)

type trayWindowClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	SmallIcon                          uintptr
}
type trayPoint struct{ X, Y int32 }
type trayMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          trayPoint
	Private        uint32
}
type trayIconData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Timeout             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                [16]byte
	BalloonIcon         uintptr
}

func TrayAvailable() bool            { return true }
func trayUTF16(value string) *uint16 { data, _ := windows.UTF16PtrFromString(value); return data }

func trayWindowProc(hwnd uintptr, message uint32, wparam, lparam uintptr) uintptr {
	trayWindows.Lock()
	actions := trayWindows.actions[hwnd]
	trayWindows.Unlock()
	switch message {
	case 0x8001:
		switch uint32(lparam) {
		case 0x0202:
			invokeTrayAction(actions, 1)
		case 0x0205, 0x007B:
			menu, _, _ := trayUser32.NewProc("CreatePopupMenu").Call()
			if menu == 0 {
				return 0
			}
			defer trayUser32.NewProc("DestroyMenu").Call(menu)
			for index, label := range []string{"Open KONE", "Pause capture", "Exit KONE"} {
				trayUser32.NewProc("AppendMenuW").Call(menu, 0, uintptr(index+1), uintptr(unsafe.Pointer(trayUTF16(label))))
			}
			var point trayPoint
			trayUser32.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&point)))
			trayUser32.NewProc("SetForegroundWindow").Call(hwnd)
			choice, _, _ := trayUser32.NewProc("TrackPopupMenuEx").Call(menu, 0x0102, uintptr(point.X), uintptr(point.Y), hwnd, 0)
			invokeTrayAction(actions, choice)
		}
		return 0
	case 0x0010:
		trayUser32.NewProc("DestroyWindow").Call(hwnd)
		return 0
	case 0x0002:
		trayUser32.NewProc("PostQuitMessage").Call(0)
		return 0
	case 0x0016:
		if wparam != 0 {
			invokeTrayAction(actions, 3)
		}
	}
	result, _, _ := trayUser32.NewProc("DefWindowProcW").Call(hwnd, uintptr(message), wparam, lparam)
	return result
}

// RunTray owns only an ordinary-permission hidden UI window. Its actions call
// the persistent controller; no network changes are performed by the UI thread.
func RunTray(ctx context.Context, actions TrayActions) error {
	if err := ctx.Err(); err != nil {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	module, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
	className := trayUTF16("KoneManagementTray")
	trayClassOnce.Do(func() {
		class := trayWindowClass{Size: uint32(unsafe.Sizeof(trayWindowClass{})), Proc: trayWindowCallback, Instance: module, ClassName: className}
		value, _, err := trayUser32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class)))
		if value == 0 {
			trayClassError = err
		}
	})
	if trayClassError != nil {
		return trayClassError
	}
	hwnd, _, err := trayUser32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(trayUTF16("KONE"))), 0, 0, 0, 0, 0, 0, 0, module, 0)
	if hwnd == 0 {
		return err
	}
	defer trayUser32.NewProc("DestroyWindow").Call(hwnd)
	trayWindows.Lock()
	trayWindows.actions[hwnd] = actions
	trayWindows.Unlock()
	defer func() { trayWindows.Lock(); delete(trayWindows.actions, hwnd); trayWindows.Unlock() }()
	icon, _, _ := trayUser32.NewProc("LoadIconW").Call(0, 32512)
	data := trayIconData{Size: uint32(unsafe.Sizeof(trayIconData{})), Window: hwnd, ID: 1, Flags: 1 | 2 | 4, Callback: 0x8001, Icon: icon}
	copy(data.Tip[:], windows.StringToUTF16("KONE — management and capture"))
	added, _, err := trayShell32.NewProc("Shell_NotifyIconW").Call(0, uintptr(unsafe.Pointer(&data)))
	if added == 0 {
		if err == syscall.Errno(0) {
			err = errors.New("Windows notification area is unavailable")
		}
		return err
	}
	defer trayShell32.NewProc("Shell_NotifyIconW").Call(2, uintptr(unsafe.Pointer(&data)))
	stop := context.AfterFunc(ctx, func() { trayUser32.NewProc("PostMessageW").Call(hwnd, 0x0010, 0, 0) })
	defer stop()
	var message trayMessage
	for {
		value, _, err := trayUser32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(value) == -1 {
			return err
		}
		if value == 0 {
			return nil
		}
		trayUser32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&message)))
		trayUser32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&message)))
	}
}

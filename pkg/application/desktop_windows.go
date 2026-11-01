package application

import (
	"context"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

var desktopMessageBox = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")

func showDesktopFailure(code int) {
	showDesktopNotice("KONE startup failed", desktopFailureMessage(code))
}

func showDesktopNotice(heading, body string) {
	message, _ := windows.UTF16PtrFromString(body)
	title, _ := windows.UTF16PtrFromString(heading)
	desktopMessageBox.Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x10)
}

func elevateForDesktop(ctx context.Context, config string, debug bool, output io.Writer) (bool, error) {
	return requestWindowsElevation(ctx, config, debug, output, processIsElevated, func(request elevationRequest) error {
		request.hidden = true
		return launchWithConfiguration(ctx, config, request, launchElevated)
	})
}

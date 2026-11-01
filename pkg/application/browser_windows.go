package application

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

type shellBrowserOpen func(windows.Handle, *uint16, *uint16, *uint16, *uint16, int32) error

func openBrowser(url string) error {
	return openBrowserWithShell(url, windows.ShellExecute, func() error {
		return windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED|windows.COINIT_DISABLE_OLE1DDE)
	}, windows.CoUninitialize)
}

func openBrowserWithShell(url string, open shellBrowserOpen, initialize func() error, uninitialize func()) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	// Shell URL handlers can use COM. Keep initialization and activation on
	// one owned thread; no command shell or console child is involved.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := initialize(); err != nil && err != syscall.Errno(1) {
		return err
	}
	defer uninitialize()
	return open(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

package locale

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func SystemLanguage() string {
	var buffer [85]uint16
	fn := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	if count, _, _ := fn.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))); count != 0 {
		return Match(windows.UTF16ToString(buffer[:]))
	}
	return Match(environmentLanguage())
}

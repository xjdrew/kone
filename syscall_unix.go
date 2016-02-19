package main

import (
	"syscall"
	"unsafe"
)

func getsockopt(fd, level, name int, v unsafe.Pointer, l *uint32) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(v), uintptr(unsafe.Pointer(l)), 0); errno != 0 {
		return error(errno)
	}
	return nil
}

func setsockopt(fd, level, name int, v unsafe.Pointer, l uint32) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(v), uintptr(l), 0); errno != 0 {
		return error(errno)
	}
	return nil
}

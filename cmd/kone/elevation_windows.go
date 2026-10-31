package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/xjdrew/kone/pkg/kone"
	"golang.org/x/sys/windows"
)

type elevationRequest struct {
	executable string
	directory  string
	args       []string
}

func elevateForWindows(ctx context.Context, config string, debug bool, output io.Writer) (bool, error) {
	return requestWindowsElevation(ctx, config, debug, output, processIsElevated, func(request elevationRequest) error {
		return launchWithConfiguration(ctx, config, request, launchElevated)
	})
}

// Shell elevation cannot supply an environment block. Never silently change
// an active rule's proxy, and never pass proxy credentials in command lines.
func launchWithConfiguration(ctx context.Context, path string, request elevationRequest, launch func(elevationRequest) error) error {
	cfg, err := kone.ParseConfig(path)
	if err != nil {
		return fmt.Errorf("revalidate configuration before UAC: %w", err)
	}
	for _, key := range []string{kone.HTTP_PROXY, kone.HTTPS_PROXY, kone.SOCKS_PROXY} {
		if os.Getenv(key) == "" && os.Getenv(strings.ToUpper(key)) == "" {
			continue
		}
		for _, rule := range cfg.Rule {
			if rule.Outbound == key {
				return fmt.Errorf("automatic UAC cannot preserve terminal proxy environment for outbound %q; put its settings in TOML and unset the override, or retry in an administrator terminal with -no-elevate", key)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return launch(request)
}

// The elevated process owns its visible console and network lifetime. Handoff
// is deliberate: closing this original terminal must not kill it mid-rollback.
func requestWindowsElevation(ctx context.Context, config string, debug bool, output io.Writer,
	query func() (bool, error), launch func(elevationRequest) error) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	elevated, err := query()
	if err != nil {
		return false, fmt.Errorf("check Windows process elevation: %w", err)
	}
	if elevated {
		return false, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("locate KONE executable: %w", err)
	}
	directory, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("locate configuration directory: %w", err)
	}
	config, err = filepath.Abs(config)
	if err != nil {
		return false, fmt.Errorf("resolve configuration path: %w", err)
	}
	args := []string{"-no-elevate", "-config", config}
	if debug {
		args = append(args, "-debug")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	fmt.Fprintln(output, "Requesting Windows administrator permission (UAC)...")
	if err := launch(elevationRequest{executable: executable, directory: directory, args: args}); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return false, fmt.Errorf("administrator authorization was cancelled; KONE did not start: %w", err)
		}
		return false, fmt.Errorf("request Windows administrator permission: %w", err)
	}
	fmt.Fprintln(output, "KONE was handed off to the administrator window. Check startup there; press Ctrl+C there to stop and restore networking.")
	return true, nil
}

func processIsElevated() (bool, error) {
	var elevation [4]byte
	var returned uint32
	if err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenElevation,
		&elevation[0], uint32(len(elevation)), &returned); err != nil {
		return false, err
	}
	if returned != uint32(len(elevation)) {
		return false, fmt.Errorf("unexpected Windows token elevation size %d", returned)
	}
	return binary.LittleEndian.Uint32(elevation[:]) != 0, nil
}

// SHELLEXECUTEINFOW has pointer-sized fields and native alignment on each
// Windows target. Do not use a shell command string or invoke runas.exe.
type shellExecuteInfo struct {
	size       uint32
	mask       uint32
	window     windows.Handle
	verb       *uint16
	file       *uint16
	parameters *uint16
	directory  *uint16
	show       int32
	instance   windows.Handle
	idList     unsafe.Pointer
	class      *uint16
	classKey   windows.Handle
	hotKey     uint32
	icon       windows.Handle
	process    windows.Handle
}

const seeMaskNoAsync = 0x00000100

func launchElevated(request elevationRequest) error {
	return executeElevation(request, callShellExecute)
}

func executeElevation(request elevationRequest, execute func(*shellExecuteInfo) error) error {
	var info shellExecuteInfo
	var err error
	info.size = uint32(unsafe.Sizeof(info))
	// Complete shell activation before the unelevated parent exits. We do not
	// request a process handle: the visible elevated window owns its lifecycle.
	info.mask = seeMaskNoAsync
	info.show = windows.SW_SHOWNORMAL
	if info.verb, err = windows.UTF16PtrFromString("runas"); err != nil {
		return err
	}
	if info.file, err = windows.UTF16PtrFromString(request.executable); err != nil {
		return err
	}
	if info.directory, err = windows.UTF16PtrFromString(request.directory); err != nil {
		return err
	}
	args := make([]string, len(request.args))
	for i, arg := range request.args {
		args[i] = windows.EscapeArg(arg)
	}
	if info.parameters, err = windows.UTF16PtrFromString(strings.Join(args, " ")); err != nil {
		return err
	}
	return execute(&info)
}

var shellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func callShellExecute(info *shellExecuteInfo) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return shellExecuteWithCOM(info,
		func() error {
			return windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED|windows.COINIT_DISABLE_OLE1DDE)
		}, windows.CoUninitialize, func(info *shellExecuteInfo) (uintptr, error) {
			result, _, err := shellExecuteEx.Call(uintptr(unsafe.Pointer(info)))
			return result, err
		})
}

func shellExecuteWithCOM(info *shellExecuteInfo, initialize func() error, uninitialize func(), execute func(*shellExecuteInfo) (uintptr, error)) error {
	// CoInitializeEx reports S_FALSE (1) for an already initialized STA. Both
	// success values require a matching CoUninitialize on this same thread.
	if err := initialize(); err != nil && err != syscall.Errno(1) {
		return fmt.Errorf("initialize Windows shell activation: %w", err)
	}
	defer uninitialize()
	result, err := execute(info)
	runtime.KeepAlive(info)
	if result == 0 {
		if err == nil || err == syscall.Errno(0) {
			return windows.ERROR_GEN_FAILURE
		}
		return err
	}
	return nil
}

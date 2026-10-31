package kone

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/windows"
)

func checkNetworkPrivileges() error {
	return requireWindowsElevation(readProcessElevation)
}

func requireWindowsElevation(read func() (bool, error)) error {
	elevated, err := read()
	if err != nil {
		return fmt.Errorf("check Windows administrator privileges: %w", err)
	}
	if !elevated {
		return fmt.Errorf("Windows TUN creation requires administrator privileges; run PowerShell or Windows Terminal as Administrator, then retry: %w", windows.ERROR_ACCESS_DENIED)
	}
	return nil
}

// Query the process token without loading Wintun or changing system settings.
// Keep query failures separate from a successfully observed unelevated token.
func readProcessElevation() (bool, error) {
	var elevation [4]byte
	var returned uint32
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenElevation,
		&elevation[0], uint32(len(elevation)), &returned)
	if err != nil {
		return false, err
	}
	if returned != uint32(len(elevation)) {
		return false, fmt.Errorf("unexpected Windows token elevation size %d", returned)
	}
	return binary.LittleEndian.Uint32(elevation[:]) != 0, nil
}

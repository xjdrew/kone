package kone

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func requireNetworkCapability(effective uint32) error {
	if effective&(uint32(1)<<unix.CAP_NET_ADMIN) == 0 {
		return errors.New("CAP_NET_ADMIN is required to configure TUN networking; grant the capability or run with administrator permission")
	}
	return nil
}

func checkNetworkPrivileges() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var capabilities [2]unix.CapUserData
	if err := unix.Capget(&header, &capabilities[0]); err != nil {
		return fmt.Errorf("inspect network privileges: %w", err)
	}
	return requireNetworkCapability(capabilities[0].Effective)
}

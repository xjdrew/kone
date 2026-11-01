package kone

import (
	"errors"
	"os"
)

func checkNetworkPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("macOS administrator authorization is required to configure TUN networking")
	}
	return nil
}

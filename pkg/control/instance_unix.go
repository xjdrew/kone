//go:build linux || darwin

package control

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func lockInstance(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("KONE is already running for this settings profile")
	}
	return file, nil
}

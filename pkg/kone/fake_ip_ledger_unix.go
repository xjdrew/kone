//go:build !windows

package kone

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func lockFakeLedger(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
func unlockFakeLedger(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
func verifyFakeLedgerPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("Fake-IP state must be private, owned by the network process and free of symlinks")
	}
	return nil
}
func syncFakeLedgerDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}
func fakeLedgerRootDirectory() (string, error) {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/KONE/fake-ip", nil
	}
	return "/var/lib/kone/fake-ip", nil
}
func fakeLedgerHostDirectory() (string, error) {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/KONE/fake-ip", nil
	}
	scope, err := fakeLedgerNamespace()
	if err != nil {
		return "", err
	}
	return filepath.Join("/var/lib/kone/fake-ip", scope), nil
}

func FakeIPNeedsAuthorization() bool { return os.Geteuid() != 0 }

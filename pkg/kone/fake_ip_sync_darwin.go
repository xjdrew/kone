package kone

import (
	"golang.org/x/sys/unix"
	"os"
)

func syncFakeLedgerFile(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	_, err := unix.FcntlInt(file.Fd(), unix.F_FULLFSYNC, 0)
	return err
}

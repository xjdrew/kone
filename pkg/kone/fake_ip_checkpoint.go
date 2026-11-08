package kone

import (
	"os"
	"path/filepath"
)

// The independently committed head detects a truncated or older WAL. An
// append is visible to DNS only after both the WAL and this head are durable.
// Restoring both files from an old backup is an operator rollback, not a safe
// recovery; that operation requires a fresh pool generation.
func (l *fakeIPLedger) checkpoint(hash string) error {
	temp, err := os.CreateTemp(l.directory, ".head-")
	if err != nil {
		return err
	}
	path := temp.Name()
	defer os.Remove(path)
	if err = verifyFakeLedgerPath(path, false); err != nil {
		temp.Close()
		return err
	}
	_, err = temp.WriteString(hash)
	if err == nil {
		err = syncFakeLedgerFile(temp)
	}
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(path, filepath.Join(l.directory, "committed-head")); err != nil {
		return err
	}
	return syncFakeLedgerDirectory(l.directory)
}
func syncFakeLedgerParents(directory string) error {
	for {
		if err := syncFakeLedgerDirectory(directory); err != nil {
			return err
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
		directory = parent
	}
}

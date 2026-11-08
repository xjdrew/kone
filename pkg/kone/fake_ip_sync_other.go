//go:build !darwin

package kone

import "os"

func syncFakeLedgerFile(file *os.File) error { return file.Sync() }

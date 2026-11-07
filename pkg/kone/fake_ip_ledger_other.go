//go:build !linux && !windows

package kone

func fakeLedgerNamespace() (string, error) { return "host", nil }

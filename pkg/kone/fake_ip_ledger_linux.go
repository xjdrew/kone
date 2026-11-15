package kone

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

func fakeLedgerNamespace() (string, error) {
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return "", err
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return "", err
	}
	if current == host {
		return "host", nil
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(boot, []byte(current)...))
	return hex.EncodeToString(sum[:12]), nil
}

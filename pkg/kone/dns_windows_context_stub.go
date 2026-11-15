//go:build !windows

package kone

import (
	"context"
	"errors"
)

func readWindowsOwnedDNSContext(context.Context, []string) (DNSSystemContext, error) {
	return DNSSystemContext{}, errors.New("Windows resolver discovery is unavailable on this platform")
}

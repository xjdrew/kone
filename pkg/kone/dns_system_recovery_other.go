//go:build !windows

package kone

import (
	"context"
	"errors"
)

func InspectSystemDNSRecovery(context.Context) ([]SystemDNSRecoveryEntry, error) { return nil, nil }

func RecoverSystemDNS(context.Context, string) error { return nil }

func readWindowsOwnedDNSContext(context.Context, []string) (DNSSystemContext, error) {
	return DNSSystemContext{}, errors.New("Windows resolver discovery is unavailable on this platform")
}

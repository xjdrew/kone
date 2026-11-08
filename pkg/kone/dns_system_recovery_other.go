//go:build !windows && !linux

package kone

import (
	"context"
)

func InspectSystemDNSRecovery(context.Context) ([]SystemDNSRecoveryEntry, error) { return nil, nil }

func RecoverSystemDNS(context.Context, string) error { return nil }

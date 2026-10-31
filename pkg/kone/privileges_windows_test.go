package kone

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWindowsElevationRequirement(t *testing.T) {
	queryFailure := errors.New("injected token query failure")
	for _, tc := range []struct {
		name     string
		elevated bool
		queryErr error
		wantErr  error
	}{
		{"elevated", true, nil, nil},
		{"unelevated", false, nil, windows.ERROR_ACCESS_DENIED},
		{"query failure", false, queryFailure, queryFailure},
		{"query access denied", false, windows.ERROR_ACCESS_DENIED, windows.ERROR_ACCESS_DENIED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := requireWindowsElevation(func() (bool, error) {
				calls++
				return tc.elevated, tc.queryErr
			})
			require.Equal(t, 1, calls)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			if tc.queryErr != nil {
				require.ErrorContains(t, err, "check Windows administrator privileges")
				require.NotContains(t, err.Error(), "as Administrator, then retry")
			} else {
				require.ErrorContains(t, err, "PowerShell or Windows Terminal as Administrator")
			}
		})
	}
}

func TestWindowsNativeOpenRequiresElevation(t *testing.T) {
	elevated, err := readProcessElevation()
	require.NoError(t, err)
	if elevated {
		t.Skip("refusal regression requires an unelevated process")
	}
	device, err := (systemNetwork{}).Open(context.Background(), CoreConfig{Network: "10.192.0.1/16"})
	require.Nil(t, device)
	require.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
	require.ErrorContains(t, err, "PowerShell or Windows Terminal as Administrator")
}

func TestWindowsNativeOpenCancellationPrecedesPrivileges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	device, err := (systemNetwork{}).Open(ctx, CoreConfig{})
	require.Nil(t, device)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
}

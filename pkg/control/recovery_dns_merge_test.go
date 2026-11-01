package control

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestRecoveryCannotClearPersistentDNSWithAbsentDevice(t *testing.T) {
	for _, journal := range []RecoveryReport{{Ownership: "none"}, {Required: true, CanClear: true, RunID: "previous-run", Ownership: "recorded"}} {
		entry := kone.SystemDNSRecoveryEntry{ID: "lease", Status: "orphaned", CanRecover: true, Message: "explicit recovery required"}
		report, err := mergeSystemDNSRecovery(journal, []kone.SystemDNSRecoveryEntry{entry}, nil, nil)
		require.NoError(t, err)
		require.True(t, report.Required)
		require.False(t, report.CanClear)
		require.Equal(t, []kone.SystemDNSRecoveryEntry{entry}, report.SystemDNS)
		require.Contains(t, report.NextAction, "administrator")
		entry.Status, entry.CanRecover = "active", false
		report, err = mergeSystemDNSRecovery(journal, []kone.SystemDNSRecoveryEntry{entry}, nil, nil)
		require.NoError(t, err)
		require.False(t, report.CanClear)
		require.Contains(t, report.NextAction, "active")
	}
	report, err := mergeSystemDNSRecovery(RecoveryReport{CanClear: true}, nil, errors.New("journal invalid"), errors.New("lease unreadable"))
	require.ErrorContains(t, err, "journal invalid")
	require.ErrorContains(t, err, "lease unreadable")
	require.True(t, report.Required)
	require.False(t, report.CanClear)
	report, err = mergeSystemDNSRecovery(RecoveryReport{CanClear: true}, nil, nil, nil)
	require.NoError(t, err)
	require.True(t, report.CanClear)
}

package control

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestAutomaticMaintenanceNeverRestoresMachineDNS(t *testing.T) {
	for _, action := range []string{"start", "reset"} {
		for _, journal := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "/dns-only", true: "/capture-record"}[journal], func(t *testing.T) {
				factoryCalls, recoveryCalls := 0, 0
				c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) {
					factoryCalls++
					return newMemoryEngine(), nil
				}, InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
					return []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), CanRecover: true, Status: "orphaned"}}, nil
				}, RecoverSystemDNS: func(context.Context, string) error { recoveryCalls++; return nil }})
				enable(t, c)
				version := c.doc.Version
				var before []byte
				if journal {
					require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "safe-capture-record"))
					var err error
					before, err = os.ReadFile(c.journalPath())
					require.NoError(t, err)
				}
				var err error
				if action == "start" {
					err = c.Start(t.Context())
				} else {
					_, err = c.ResetConfiguration(t.Context(), version)
				}
				require.ErrorIs(t, err, errSystemDNSRecoveryRequired)
				require.Zero(t, factoryCalls, "capture cannot start before explicit resolver recovery")
				require.Zero(t, recoveryCalls, "automatic maintenance cannot launch UAC or mutate NRPT")
				require.Equal(t, version, c.doc.Version, "reset cannot discard intent while a DNS lease remains")
				require.Equal(t, "paused", c.State().State)
				if journal {
					after, err := os.ReadFile(c.journalPath())
					require.NoError(t, err)
					require.Equal(t, before, after)
				}
			})
		}
	}
}

func TestExplicitDNSRecoveryPreservesReplacementCaptureEpoch(t *testing.T) {
	for _, previous := range []bool{false, true} {
		t.Run(map[bool]string{false: "previously-absent", true: "previous-record"}[previous], func(t *testing.T) {
			var c *Controller
			remaining := true
			c = testController(t, Options{InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
				if remaining {
					return []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), CanRecover: true}}, nil
				}
				return nil, nil
			}, RecoverSystemDNS: func(context.Context, string) error {
				remaining = false
				if previous {
					require.NoError(t, c.removeRecoveryJournal("previous-capture-epoch"))
				}
				return c.writeRecoveryJournal(c.doc.Config, "replacement-capture-epoch")
			}})
			if previous {
				require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "previous-capture-epoch"))
			}
			require.ErrorContains(t, c.Recover(t.Context()), "changed during DNS restoration")
			record, err := c.readRecoveryJournal(false)
			require.NoError(t, err)
			require.Equal(t, "replacement-capture-epoch", record.RunID)
			require.NotEmpty(t, c.State().LastError)
		})
	}
}

func TestCancelledRecoveryInspectionCannotMutateDNSOrDiscardJournal(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	c := testController(t, Options{InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
		cancel()
		return []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), CanRecover: true}}, nil
	}, RecoverSystemDNS: func(context.Context, string) error { calls++; return nil }})
	require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "cancelled-capture-record"))
	require.ErrorIs(t, c.Recover(ctx), context.Canceled)
	require.Zero(t, calls)
	require.FileExists(t, c.journalPath())
}

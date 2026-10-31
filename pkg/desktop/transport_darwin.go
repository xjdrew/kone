package desktop

import (
	"context"
	"os"

	"github.com/xjdrew/kone/pkg/kone"
)

type LaunchHelper func(context.Context, string, []string) error

// Native CI verifies authenticated ordinary-user/root IPC, disconnect cleanup,
// and real system/mixed UTUN traffic with ownership-preserving rollback.
// Signing/notarization remains a separate distribution requirement.
const darwinHelperValidated = true

func PrivilegeSeparationAvailable() bool { return darwinHelperValidated }
func NeedsHelper() bool                  { return darwinHelperValidated && os.Geteuid() != 0 }
func NewEngine(cfg *kone.KoneConfig, launch LaunchHelper) (*RemoteEngine, error) {
	return darwinNewEngine(cfg, launch)
}
func RunNetworkHelper(ctx context.Context, base string, parentPID uint32) error {
	return runDarwinNetworkHelper(ctx, base, parentPID, nil)
}
func Preflight(ctx context.Context, cfg *kone.KoneConfig) kone.PreflightReport {
	report := kone.Preflight(ctx, cfg)
	if !NeedsHelper() {
		return report
	}
	report.Ready = true
	for index := range report.Issues {
		issue := &report.Issues[index]
		if issue.Code == "privileges" {
			issue.Severity = "info"
			issue.Message = "Starting capture requires explicit macOS administrator authorization for the network helper"
		}
		if issue.Severity == "error" {
			report.Ready = false
		}
	}
	return report
}

package desktop

import (
	"context"
	"os"
	"os/exec"

	"github.com/xjdrew/kone/pkg/kone"
	"golang.org/x/sys/unix"
)

type LaunchHelper func(context.Context, string, []string) error

func PrivilegeSeparationAvailable() bool { return true }
func NeedsHelper() bool {
	if os.Geteuid() == 0 {
		return false
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var capabilities [2]unix.CapUserData
	return unix.Capget(&header, &capabilities[0]) != nil || capabilities[0].Effective&(1<<unix.CAP_NET_ADMIN) == 0
}
func NewEngine(cfg *kone.KoneConfig, launch LaunchHelper) (*RemoteEngine, error) {
	return linuxNewEngine(cfg, launch)
}
func RunNetworkHelper(ctx context.Context, base string, parentPID uint32) error {
	return runLinuxNetworkHelper(ctx, base, parentPID, nil)
}
func Preflight(ctx context.Context, cfg *kone.KoneConfig) kone.PreflightReport {
	report := kone.Preflight(ctx, cfg)
	if !NeedsHelperForConfig(cfg) {
		return report
	}
	_, err := exec.LookPath("pkexec")
	return linuxAuthorizationPreflight(report, err == nil)
}

func linuxAuthorizationPreflight(report kone.PreflightReport, available bool) kone.PreflightReport {
	report.Ready = true
	for index := range report.Issues {
		issue := &report.Issues[index]
		if issue.Code == "privileges" {
			if available {
				issue.Severity = "info"
				issue.Message = "Enabling capture requests administrator authorization through the Linux host's polkit authentication agent"
			} else {
				issue.Code = "authorization_unavailable"
				issue.Message = "Install pkexec and a polkit authentication agent on the Linux host, or start KONE with network administration privileges and the same profile directory"
			}
		}
		if issue.Severity == "error" {
			report.Ready = false
		}
	}
	return report
}

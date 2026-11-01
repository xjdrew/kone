package application

import (
	"context"
	"log/slog"
	"time"
)

// The tray dispatcher runs each action asynchronously with a bounded slot.
// Capture failures leave management available so the owner can repair settings.
func captureTrayAction(parent context.Context, action string, operation func(context.Context) error, localAccess func() (string, error), options runOptions) func() {
	return func() {
		ctx, cancel := context.WithTimeout(parent, 20*time.Second)
		defer cancel()
		if err := operation(ctx); err != nil {
			slog.Error("Capture operation failed", "operation", action, "error", err)
			if err := openCaptureDiagnostics(localAccess, options.browser); err != nil {
				slog.Error("Could not open capture diagnostics", "operation", action, "error", err)
			}
			if options.desktop {
				options.captureNotice(action)
			}
		}
	}
}

func openCaptureDiagnostics(localAccess func() (string, error), browser func(string) error) error {
	local, err := localAccess()
	if err != nil {
		return err
	}
	target, err := localManagementPageURL(local, "diagnostics")
	if err != nil {
		return err
	}
	return browser(target)
}

func showCaptureFailure(action string) {
	showDesktopNotice("KONE 操作未完成", captureFailureMessage(action))
}

func captureFailureMessage(action string) string {
	if action == "start" {
		return "未能启用接管。请在管理页面查看诊断与日志；如果 TUN 入站尚未启用，请到“入站”启用、保存后重试。管理服务仍然可用。"
	}
	return "未能暂停接管。请在管理页面查看当前状态、诊断与日志，确认接管与恢复结果。管理服务仍然可用。"
}

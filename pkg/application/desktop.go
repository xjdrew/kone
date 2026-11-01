package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/logstore"
)

// RunDesktop opens persistent management and its browser interface without
// printing the setup URL. -no-browser leaves management in the native tray.
func RunDesktop(ctx context.Context, args []string, version string) int {
	return runDesktop(ctx, args, version, showDesktopFailure)
}

func runDesktop(ctx context.Context, args []string, version string, notify func(int, string)) int {
	logs := logstore.New()
	handler := slog.NewJSONHandler(io.Discard, nil)
	slog.SetDefault(slog.New(logs.Handler(handler, "desktop")).With("service", "kone"))
	var startupFailure error
	code := runWithOptions(ctx, args, io.Discard, logs.Writer("desktop"), elevateForDesktop, runOptions{
		version: version, desktop: true, logs: logs,
		startupFailure: func(err error) { startupFailure = err },
	})
	if code != 0 && !networkHelperInvocation(args) {
		notify(code, desktopFailureMessage(code, startupFailure))
	}
	return code
}

func networkHelperInvocation(args []string) bool {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" || !strings.HasPrefix(argument, "-") {
			break
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		if name == "network-helper" {
			return true
		}
		switch name {
		case "config", "data-dir", "listen", "parent-pid":
			if !hasValue {
				index++
			}
		case "version", "debug", "check", "no-elevate", "manage", "no-browser", "no-tray":
		default:
			return false
		}
	}
	return false
}

func desktopFailureMessage(code int, cause error) string {
	// Never include raw flag values, configuration contents or bootstrap URLs.
	if errors.Is(cause, control.ErrPasswordFormatUnsupported) {
		return "管理密码格式已更新，旧认证文件无法使用。\n\n请退出 KONE，备份并移出配置目录中的 auth.json，再重新启动并设置管理密码。\n\n保留 settings.json，代理和规则等配置无需重置。"
	}
	return fmt.Sprintf("KONE could not start (exit %d). Open kone-cli in a terminal to inspect the configuration and startup diagnostics.", code)
}

func showBrowserFailure() {
	showBrowserNotice("KONE 管理已在后台运行", browserFailureMessage())
}

func browserFailureMessage() string {
	return "无法打开默认浏览器。管理服务已在后台运行，关闭此提示不会退出 KONE。\n\n请打开托盘或菜单栏中的 KONE 图标，重新进入管理页面。"
}

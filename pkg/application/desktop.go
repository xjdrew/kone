package application

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/xjdrew/kone/pkg/logstore"
)

// RunDesktop opens persistent management without printing its bootstrap URL or
// opening the browser. The native tray supplies the explicit browser action.
func RunDesktop(ctx context.Context, args []string, version string) int {
	return runDesktop(ctx, args, version, showDesktopFailure)
}

func runDesktop(ctx context.Context, args []string, version string, notify func(int)) int {
	logs := logstore.New()
	handler := slog.NewJSONHandler(io.Discard, nil)
	slog.SetDefault(slog.New(logs.Handler(handler, "desktop")).With("service", "kone"))
	code := runWithOptions(ctx, args, io.Discard, logs.Writer("desktop"), elevateForDesktop, runOptions{version: version, desktop: true, logs: logs})
	if code != 0 && !networkHelperInvocation(args) {
		notify(code)
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

func desktopFailureMessage(code int) string {
	// Never include raw flag values, configuration contents or bootstrap URLs.
	return fmt.Sprintf("KONE could not start (exit %d). Open kone-cli in a terminal to inspect the configuration and startup diagnostics.", code)
}

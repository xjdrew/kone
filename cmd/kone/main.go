package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/xjdrew/kone/pkg/application"
)

var VERSION = "0.3-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := 0
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		code = application.RunDesktop(ctx, os.Args[1:], VERSION)
	} else {
		code = application.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, VERSION)
	}
	stop()
	os.Exit(code)
}

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/xjdrew/kone/pkg/application"
)

var VERSION = "0.3-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := application.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, VERSION)
	stop()
	os.Exit(code)
}

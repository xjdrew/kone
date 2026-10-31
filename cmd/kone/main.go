package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/xjdrew/kone/pkg/kone"
)

var VERSION = "0.3-dev"

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runContextWithElevation(ctx, args, stdout, stderr, elevateForWindows)
}

type elevationFunc func(context.Context, string, bool, io.Writer) (bool, error)

func runContextWithElevation(ctx context.Context, args []string, stdout, stderr io.Writer, elevate elevationFunc) int {
	flags := flag.NewFlagSet("kone", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.Bool("version", false, "Print version")
	debug := flags.Bool("debug", false, "Enable structured debug logs")
	check := flags.Bool("check", false, "Validate configuration without changing system networking")
	noElevate := flags.Bool("no-elevate", false, "Do not request Windows UAC elevation (for services and headless use)")
	filename := flags.String("config", "config.toml", "TOML configuration file")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *version {
		fmt.Fprintf(stdout, "Version: %s\n", VERSION)
		return 0
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "expected at most one configuration filename")
		return 2
	}
	if flags.NArg() == 1 {
		explicit := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "config" {
				explicit = true
			}
		})
		if explicit {
			fmt.Fprintln(stderr, "use either -config or a positional filename")
			return 2
		}
		*filename = flags.Arg(0)
	}
	cfg, err := kone.ParseConfig(*filename)
	if err != nil {
		fmt.Fprintf(stderr, "Configuration error: %s\n", err)
		return 2
	}
	if err := kone.ConfigureLogging(stderr, cfg.General, *debug); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *check {
		fmt.Fprintln(stdout, "Configuration valid")
		return 0
	}
	if !*noElevate {
		handedOff, err := elevate(ctx, *filename, *debug, stderr)
		if err != nil {
			slog.Error("Windows administrator authorization failed", "error", err)
			return 3
		}
		if handedOff {
			return 0
		}
	}
	slog.Info("Starting KONE", "config", *filename, "version", VERSION)
	one, err := kone.FromConfig(cfg)
	if err != nil {
		slog.Error("Startup failed", "error", err)
		return 3
	}
	if err := one.Run(ctx); err != nil {
		slog.Error("KONE stopped", "error", err)
		return 3
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

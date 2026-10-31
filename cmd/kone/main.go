package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/geoip"
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
	manage := flags.Bool("manage", false, "Open persistent management without enabling capture")
	directory := flags.String("data-dir", "", "Management profile directory (defaults to the user configuration directory)")
	listen := flags.String("listen", "127.0.0.1:9200", "Management loopback IP and port")
	noBrowser := flags.Bool("no-browser", false, "Print the management URL without opening a browser")
	noTray := flags.Bool("no-tray", false, "Disable the native management tray")
	helperPipe := flags.String("network-helper", "", "Internal authenticated network helper pipe")
	helperParent := flags.Uint64("parent-pid", 0, "Internal network helper parent identity")
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
	if *helperPipe != "" {
		if *helperParent == 0 || *helperParent > uint64(^uint32(0)) {
			fmt.Fprintln(stderr, "Invalid network helper parent identity")
			return 2
		}
		if err := desktop.RunNetworkHelper(ctx, *helperPipe, uint32(*helperParent)); err != nil {
			fmt.Fprintln(stderr, "Network helper failed:", err)
			return 3
		}
		return 0
	}
	if *helperParent != 0 {
		fmt.Fprintln(stderr, "Network helper identity requires a helper pipe")
		return 2
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "expected at most one configuration filename")
		return 2
	}
	explicitConfig := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			explicitConfig = true
		}
	})
	if flags.NArg() == 1 {
		if explicitConfig {
			fmt.Fprintln(stderr, "use either -config or a positional filename")
			return 2
		}
		*filename = flags.Arg(0)
		explicitConfig = true
	}
	if *manage && explicitConfig {
		fmt.Fprintln(stderr, "management loads its saved profile; use the management interface to edit settings")
		return 2
	}
	if !*check && (*manage || !explicitConfig) {
		if ctx.Err() != nil {
			return 0
		}
		options := control.Options{Directory: *directory, Version: VERSION}
		options.ConfigureLogging = func(general kone.GeneralConfig) error { return kone.ConfigureLogging(stderr, general, *debug) }
		if desktop.PrivilegeSeparationAvailable() {
			if options.Directory == "" {
				var err error
				options.Directory, err = control.DefaultDirectory()
				if err != nil {
					fmt.Fprintln(stderr, "Cannot locate the management profile")
					return 3
				}
			}
			options.Preflight = desktop.Preflight
			options.Factory = func(cfg *kone.KoneConfig) (control.Engine, error) {
				repository, err := geoip.OpenRepository(filepath.Join(options.Directory, "geoip"))
				if err != nil {
					return nil, fmt.Errorf("saved GeoIP data needs repair: %w", err)
				}
				if desktop.NeedsHelper() {
					engine, err := desktop.NewEngine(cfg, launchManagedHelper)
					if err != nil {
						return nil, err
					}
					if setter, ok := any(engine).(interface{ SetGeoIPDatabase(*geoip.Database) error }); ok {
						if err = setter.SetGeoIPDatabase(repository.Current()); err != nil {
							return nil, err
						}
					} else if !repository.Current().Metadata().Builtin {
						return nil, fmt.Errorf("network helper cannot load this GeoIP dataset")
					}
					return engine, nil
				}
				return kone.FromConfig(cfg, kone.WithGeoIPDatabase(repository.Current()))
			}
		}
		manager, err := control.New(options)
		if err != nil {
			fmt.Fprintf(stderr, "Management initialization failed: %s\n", err)
			return 3
		}
		defer manager.Close()
		trayCtx, stopTray := context.WithCancel(ctx)
		defer stopTray()
		err = manager.Serve(ctx, *listen, func(url string) {
			fmt.Fprintf(stdout, "KONE management (capture paused): %s\n", url)
			if !*noBrowser {
				if err := openBrowser(url); err != nil {
					fmt.Fprintln(stderr, "Could not open a browser; open the printed local URL")
				}
			}
			if !*noTray && !*noBrowser && desktop.TrayAvailable() {
				go func() {
					err := desktop.RunTray(trayCtx, desktop.TrayActions{
						Open: func() {
							if local, err := manager.LocalAccessURL(); err == nil {
								_ = openBrowser(local)
							}
						},
						Pause: func() {
							ctx, cancel := context.WithTimeout(trayCtx, 20*time.Second)
							defer cancel()
							if err := manager.Pause(ctx); err != nil {
								slog.Warn("Capture pause failed", "error", err)
							}
						},
						Start: func() {
							ctx, cancel := context.WithTimeout(trayCtx, 40*time.Second)
							defer cancel()
							if err := manager.Start(ctx); err != nil {
								slog.Warn("Capture start failed", "error", err)
							}
						},
						Diagnostics: func() {
							if local, err := manager.LocalAccessURL(); err == nil {
								_ = openBrowser(local)
							}
						},
						State: func() string { return manager.State().DataState },
						Exit: func() {
							if err := manager.Close(); err != nil {
								slog.Error("KONE cleanup failed", "error", err)
							}
						},
					})
					if err != nil {
						slog.Warn("Management tray unavailable", "error", err)
					}
				}()
			}
		})
		if err != nil {
			fmt.Fprintf(stderr, "Management stopped: %s\n", err)
			return 3
		}
		return 0
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

func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		command = exec.Command("open", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go command.Wait()
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

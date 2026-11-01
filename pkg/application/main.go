package application

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

const defaultVersion = "0.3-dev"

// Run preserves the console application's command-line and lifecycle contract.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	return runWithOptions(ctx, args, stdout, stderr, elevateForWindows, runOptions{version: version})
}

type runOptions struct {
	version        string
	desktop        bool
	logs           *logstore.Store
	browser        func(string) error
	tray           func(context.Context, desktop.TrayActions) error
	trayAvailable  func() bool
	captureNotice  func(string)
	startupFailure func(error)
}

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runContextWithElevation(ctx, args, stdout, stderr, elevateForWindows)
}

type elevationFunc func(context.Context, string, bool, io.Writer) (bool, error)

func runContextWithElevation(ctx context.Context, args []string, stdout, stderr io.Writer, elevate elevationFunc) int {
	return runWithOptions(ctx, args, stdout, stderr, elevate, runOptions{version: defaultVersion})
}

func runWithOptions(ctx context.Context, args []string, stdout, stderr io.Writer, elevate elevationFunc, options runOptions) int {
	if options.logs == nil {
		options.logs = logstore.New()
	}
	if options.browser == nil {
		options.browser = openBrowser
	}
	if options.tray == nil {
		options.tray = desktop.RunTray
	}
	if options.trayAvailable == nil {
		options.trayAvailable = desktop.TrayAvailable
	}
	if options.captureNotice == nil {
		options.captureNotice = showCaptureFailure
	}
	configureLogging := func(general kone.GeneralConfig, debug bool) error {
		output := stderr
		if options.desktop {
			output = io.Discard
		}
		handler, err := kone.NewLoggingHandler(output, general, debug)
		if err != nil {
			return err
		}
		slog.SetDefault(slog.New(options.logs.Handler(handler, "management")).With("service", "kone"))
		return nil
	}
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
		fmt.Fprintf(stdout, "Version: %s\n", options.version)
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
		if options.desktop && !*noTray && !options.trayAvailable() {
			fmt.Fprintln(stderr, "Native desktop tray is unavailable; use kone-cli for console management")
			return 3
		}
		if err := configureLogging(kone.DefaultConfig().General, *debug); err != nil {
			fmt.Fprintln(stderr, "Could not initialize management logging")
			return 3
		}
		slog.Info("Starting KONE management", "stage", "startup", "version", options.version, "desktop", options.desktop, "capture", "paused")
		controlOptions := control.Options{Directory: *directory, Version: options.version, LogStore: options.logs}
		controlOptions.RecoverSystemDNS = func(ctx context.Context, id string) error {
			return selectSystemDNSRecovery(ctx, id, func() bool { return runtime.GOOS == "windows" && desktop.NeedsHelper() }, kone.RecoverSystemDNS,
				func(ctx context.Context, id string) error {
					return desktop.RecoverSystemDNS(ctx, id, launchManagedHelper)
				})
		}
		controlOptions.ConfigureLogging = func(general kone.GeneralConfig) error { return configureLogging(general, *debug) }
		if desktop.PrivilegeSeparationAvailable() {
			if controlOptions.Directory == "" {
				var err error
				controlOptions.Directory, err = control.DefaultDirectory()
				if err != nil {
					fmt.Fprintln(stderr, "Cannot locate the management profile")
					return 3
				}
			}
			controlOptions.Preflight = desktop.Preflight
			controlOptions.Factory = func(cfg *kone.KoneConfig) (control.Engine, error) {
				repository, err := geoip.OpenRepository(filepath.Join(controlOptions.Directory, "geoip"))
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
		manager, err := control.New(controlOptions)
		if err != nil {
			slog.Error("Management initialization failed", "stage", "startup", "error", err)
			fmt.Fprintf(stderr, "Management initialization failed: %s\n", err)
			if options.startupFailure != nil {
				options.startupFailure(err)
			}
			return 3
		}
		defer manager.Close()
		trayCtx, stopTray := context.WithCancel(ctx)
		defer stopTray()
		trayFailure := make(chan error, 1)
		openInitial, startTray := managementPresentation(options.desktop, *noBrowser, *noTray)
		err = manager.Serve(ctx, *listen, func(url string) {
			slog.Info("Local management is ready", "stage", "listen", "capture", manager.State().DataState, "saved_version", manager.State().SavedVersion)
			if !options.desktop {
				fmt.Fprintf(stdout, "KONE management (capture paused): %s\n", url)
			}
			if openInitial {
				slog.Info("Opening local management in the browser", "stage", "browser")
				if err := options.browser(url); err != nil {
					slog.Warn("Could not open the management browser", "stage", "browser", "error", err)
					fmt.Fprintln(stderr, "Could not open a browser; open the printed local URL")
				}
			}
			if startTray && options.trayAvailable() {
				slog.Info("Starting native management tray", "stage", "tray")
				go func() {
					err := options.tray(trayCtx, desktop.TrayActions{
						Open: func() {
							slog.Info("Opening local management from the tray", "stage", "browser")
							if local, err := manager.LocalAccessURL(); err == nil {
								_ = options.browser(local)
							}
						},
						Pause: captureTrayAction(trayCtx, "pause", manager.Pause, manager.LocalAccessURL, options),
						Start: captureTrayAction(trayCtx, "start", manager.Start, manager.LocalAccessURL, options),
						Diagnostics: func() {
							slog.Info("Opening capture diagnostics from the tray", "stage", "diagnostics")
							if local, err := manager.LocalAccessURL(); err == nil {
								if target, err := localManagementPageURL(local, "diagnostics"); err == nil {
									_ = options.browser(target)
								}
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
						if options.desktop {
							trayFailure <- err
							_ = manager.Close()
						}
					}
				}()
			}
		})
		select {
		case failure := <-trayFailure:
			err = failure
		default:
		}
		if err != nil {
			slog.Error("Management service stopped with an error", "stage", "shutdown", "error", err)
			fmt.Fprintf(stderr, "Management stopped: %s\n", err)
			return 3
		}
		slog.Info("Management service stopped", "stage", "shutdown")
		return 0
	}
	cfg, err := kone.ParseConfig(*filename)
	if err != nil {
		fmt.Fprintf(stderr, "Configuration error: %s\n", err)
		return 2
	}
	if err := configureLogging(cfg.General, *debug); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *check {
		if err := cfg.ValidateGeoIPFile(); err != nil {
			fmt.Fprintf(stderr, "GeoIP configuration error: %s\n", err)
			return 2
		}
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
	slog.Info("Starting KONE", "config", *filename, "version", options.version)
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

func managementPresentation(gui, noBrowser, noTray bool) (openInitial, startTray bool) {
	return !gui && !noBrowser, !noTray && (gui || !noBrowser)
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
	prepareBackground(command)
	if err := command.Start(); err != nil {
		return err
	}
	go command.Wait()
	return nil
}

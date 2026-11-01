package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xjdrew/kone/pkg/dnsconfig"
	commandutil "github.com/xjdrew/kone/pkg/internal/command"
)

type NetworkChange struct {
	Kind       string    `json:"kind"`
	Changed    []string  `json:"changed"`
	ObservedAt time.Time `json:"observed_at"`
	Error      string    `json:"error,omitempty"`
}

type networkFingerprint struct{ interfaces, dns, routes string }

func fingerprint(values []string) string {
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}

// sampleNetwork observes only; these commands cannot install routes, change DNS
// or alter an HTTP proxy. Sampling starts after capture is ready so its own
// setup does not trigger a false external-network change.
func sampleNetwork(ctx context.Context, ownedTunName string) (networkFingerprint, error) {
	var result networkFingerprint
	interfaces, err := net.Interfaces()
	if err != nil {
		return result, err
	}
	var values []string
	for _, device := range interfaces {
		if device.Name == ownedTunName || device.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := device.Addrs()
		if err != nil {
			return result, err
		}
		values = append(values, device.Name+":"+strconv.Itoa(device.Index)+":"+device.Flags.String())
		for _, address := range addresses {
			values = append(values, device.Name+":"+address.String())
		}
	}
	result.interfaces = fingerprint(values)
	dns := dnsconfig.ReadDnsConfig()
	if dns == nil {
		return result, errors.New("system DNS inspection returned no result")
	}
	if dns.Err != nil {
		return result, errors.New("system DNS configuration cannot be inspected")
	}
	values = append([]string(nil), dns.Servers...)
	for _, search := range dns.Search {
		values = append(values, "search:"+search)
	}
	result.dns = fingerprint(values)
	var routeData []byte
	if runtime.GOOS == "linux" {
		routeData, err = os.ReadFile("/proc/net/route")
	} else {
		queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var command *exec.Cmd
		if runtime.GOOS == "windows" {
			command = exec.CommandContext(queryCtx, "route.exe", "print", "-4")
		} else {
			command = exec.CommandContext(queryCtx, "route", "-n", "get", "default")
		}
		commandutil.Background(command)
		routeData, err = command.Output()
	}
	if err != nil {
		return result, errors.New("system route inspection failed")
	}
	// Route order is not an ownership signal; normalize complete lines so a
	// harmless ordering change does not pause a healthy engine.
	lines := strings.Split(strings.ReplaceAll(string(routeData), "\r\n", "\n"), "\n")
	if runtime.GOOS == "linux" {
		values = nil
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 8 && fields[0] != "Iface" {
				values = append(values, strings.Join([]string{fields[0], fields[1], fields[2], fields[3], fields[6], fields[7]}, " "))
			}
		}
		lines = values
	} else if runtime.GOOS == "darwin" {
		values = nil
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "gateway:") || strings.HasPrefix(line, "interface:") || strings.HasPrefix(line, "flags:") {
				values = append(values, line)
			}
		}
		lines = values
	}
	result.routes = fingerprint(lines)
	return result, ctx.Err()
}

// WatchNetworkChanges emits at most one external environment change or read
// failure, then closes. The controller must pause through its normal lifecycle,
// explain the reason, and preflight again before the user resumes capture.
func WatchNetworkChanges(ctx context.Context, ownedTunName string, interval time.Duration) <-chan NetworkChange {
	if interval < time.Second {
		interval = 5 * time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	return watchNetworkChanges(ctx, interval, func(ctx context.Context) (networkFingerprint, error) { return sampleNetwork(ctx, ownedTunName) })
}

func watchNetworkChanges(ctx context.Context, interval time.Duration, sample func(context.Context) (networkFingerprint, error)) <-chan NetworkChange {
	changes := make(chan NetworkChange, 1)
	go func() {
		defer close(changes)
		baseline, err := sample(ctx)
		emit := func(err error, changed []string) {
			if ctx.Err() != nil {
				return
			}
			event := NetworkChange{Kind: "environment_changed", Changed: changed, ObservedAt: time.Now()}
			if err != nil {
				event.Kind = "inspection_failed"
				event.Error = "The host network environment could not be inspected safely"
			}
			changes <- event
		}
		if err != nil {
			emit(err, nil)
			return
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current, err := sample(ctx)
				if err != nil {
					emit(err, nil)
					return
				}
				var changed []string
				if current.interfaces != baseline.interfaces {
					changed = append(changed, "interfaces")
				}
				if current.dns != baseline.dns {
					changed = append(changed, "dns")
				}
				if current.routes != baseline.routes {
					changed = append(changed, "routes")
				}
				if len(changed) > 0 {
					emit(nil, changed)
					return
				}
			}
		}
	}()
	return changes
}

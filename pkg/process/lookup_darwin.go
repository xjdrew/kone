package process

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Supported() bool { _, err := os.Stat("/usr/sbin/lsof"); return err == nil }

func darwinOwner(data []byte, query Query) (uint32, error) {
	var pid, owner uint32
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			value, err := strconv.ParseUint(line[1:], 10, 32)
			if err != nil {
				pid = 0
			} else {
				pid = uint32(value)
			}
		case 'n':
			parts := strings.Split(line[1:], "->")
			local := parts[0]
			if strings.HasPrefix(local, "*:") {
				local = "0.0.0.0:" + strings.TrimPrefix(local, "*:")
			}
			endpoint, err := netip.ParseAddrPort(local)
			if err != nil {
				continue
			}
			if endpoint.Port() != query.Source.Port() || endpoint.Addr() != query.Source.Addr().Unmap() && (query.Protocol != "udp" || !endpoint.Addr().IsUnspecified()) {
				continue
			}
			if len(parts) == 2 {
				remote, err := netip.ParseAddrPort(parts[1])
				if err != nil || remote != query.Destination {
					continue
				}
			} else if query.Protocol != "udp" {
				continue
			}
			if pid == 0 {
				continue
			}
			if owner != 0 && owner != pid {
				return 0, errors.New("socket owner is ambiguous")
			}
			owner = pid
		}
	}
	if owner == 0 {
		return 0, errors.New("socket owner unavailable or access denied")
	}
	return owner, nil
}

func macOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	// Set a fixed locale for machine parsing. No process arguments or environment
	// are collected; ps is explicitly asked only for start time and executable.
	command.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	var output macBoundedOutput
	command.Stdout = &output
	command.WaitDelay = 100 * time.Millisecond
	err := command.Run()
	if output.truncated {
		return nil, errors.New("process inspection output exceeded bound")
	}
	return output.data, err
}

type macBoundedOutput struct {
	data      []byte
	truncated bool
}

func (w *macBoundedOutput) Write(data []byte) (int, error) {
	n := len(data)
	remaining := 1024*1024 - len(w.data)
	if remaining < len(data) {
		w.data = append(w.data, data[:remaining]...)
		w.truncated = true
	} else {
		w.data = append(w.data, data...)
	}
	return n, nil
}

func darwinIdentity(ctx context.Context, pid uint32) (string, time.Time, error) {
	data, err := macOutput(ctx, "/bin/ps", "-p", strconv.FormatUint(uint64(pid), 10), "-o", "lstart=", "-o", "comm=")
	if err != nil {
		return "", time.Time{}, err
	}
	line := strings.TrimSpace(string(data))
	if len(line) < 26 || strings.ContainsAny(line, "\r\n\x00") {
		return "", time.Time{}, errors.New("invalid process identity")
	}
	started, err := time.ParseInLocation(time.ANSIC, line[:24], time.Local)
	if err != nil {
		return "", time.Time{}, err
	}
	return strings.TrimSpace(line[24:]), started, nil
}

func lookupNative(ctx context.Context, query Query) (Result, error) {
	args := []string{"-nP", "-a", "-i4" + strings.ToUpper(query.Protocol) + ":" + strconv.Itoa(int(query.Source.Port())), "-Fpn"}
	data, err := macOutput(ctx, "/usr/sbin/lsof", args...)
	if err != nil {
		return Result{}, err
	}
	pid, err := darwinOwner(data, query)
	if err != nil {
		return Result{}, err
	}
	path, started, err := darwinIdentity(ctx, pid)
	if err != nil {
		return Result{}, err
	}
	if query.ObservedAt.Sub(started) < time.Second {
		return Result{}, errors.New("process is too recent to validate at system timestamp resolution")
	}
	data, err = macOutput(ctx, "/usr/sbin/lsof", args...)
	if err != nil {
		return Result{}, err
	}
	confirmed, err := darwinOwner(data, query)
	if err != nil || confirmed != pid {
		return Result{}, errors.New("socket endpoint was reused")
	}
	confirmedPath, confirmedStart, err := darwinIdentity(ctx, pid)
	if err != nil || confirmedPath != path || !confirmedStart.Equal(started) {
		return Result{}, errors.New("process exited or PID was reused")
	}
	return Result{Status: "matched", PID: pid, Path: path, Name: filepath.Base(path), StartedAt: started, Source: "darwin_lsof_ps_starttime", Reason: "socket endpoint and process start time validated twice"}, nil
}

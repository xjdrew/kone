package desktop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
	"golang.org/x/sys/unix"
)

// This transport is activated only after its native ownership/lifecycle tests
// pass. It shares the already-tested cross-platform network RPC contract.
func darwinNewEngine(cfg *kone.KoneConfig, launch LaunchHelper) (*RemoteEngine, error) {
	if launch == nil {
		return nil, errors.New("macOS authorization launcher is unavailable")
	}
	return NewRemote(cfg, func(ctx context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return connectDarwin(ctx, launch)
	})
}

func darwinPeer(conn net.Conn) (uint32, uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("private helper requires a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var pid int
	var uid uint32
	var inspectErr error
	err = raw.Control(func(fd uintptr) {
		pid, inspectErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if inspectErr != nil {
			return
		}
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			inspectErr = err
			return
		}
		uid = credentials.Uid
	})
	if err != nil {
		return 0, 0, err
	}
	if inspectErr != nil {
		return 0, 0, inspectErr
	}
	if pid <= 0 {
		return 0, 0, errors.New("Unix peer has no process identity")
	}
	return uint32(pid), uid, nil
}

func darwinProcessIdentity(parent context.Context, pid uint32) (string, string, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/ps", "-ww", "-p", strconv.FormatUint(uint64(pid), 10), "-o", "lstart=", "-o", "comm=")
	command.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	data, err := command.Output()
	if err != nil {
		return "", "", errors.New("cannot inspect private helper executable identity")
	}
	line := strings.TrimSpace(string(data))
	if len(line) < 26 || len(line) > 8192 || strings.ContainsAny(line, "\r\n\x00") {
		return "", "", errors.New("invalid private helper process identity")
	}
	if _, err := time.ParseInLocation(time.ANSIC, line[:24], time.Local); err != nil {
		return "", "", errors.New("invalid private helper process start time")
	}
	path := strings.TrimSpace(line[24:])
	if !filepath.IsAbs(path) {
		return "", "", errors.New("system did not expose an absolute private helper executable")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", err
	}
	return path, line[:24], nil
}

func verifyDarwinPeer(ctx context.Context, pid uint32) error {
	if pid == 0 || pid == uint32(os.Getpid()) {
		return errors.New("invalid private helper peer process")
	}
	first, started, err := darwinProcessIdentity(ctx, pid)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	if filepath.Clean(first) != filepath.Clean(self) {
		return errors.New("private helper peer is not the same KONE executable")
	}
	second, confirmed, err := darwinProcessIdentity(ctx, pid)
	if err != nil || second != first || confirmed != started {
		return errors.New("private helper peer exited or its PID was reused")
	}
	return nil
}

func acceptDarwin(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() { conn, err := listener.Accept(); done <- result{conn, err} }()
	select {
	case value := <-done:
		return value.conn, value.err
	case <-ctx.Done():
		listener.Close()
		value := <-done
		if value.conn != nil {
			value.conn.Close()
		}
		return nil, ctx.Err()
	}
}

func connectDarwin(parent context.Context, launch LaunchHelper) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	// Darwin's Unix socket path limit is short; user TMPDIR may already consume
	// most of it. A fresh 0700 directory under system /tmp is private and bounded.
	directory, err := os.MkdirTemp("/tmp", "kone-helper-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0700); err != nil {
		return nil, nil, err
	}
	base := filepath.Join(directory, "kone")
	commands, err := net.Listen("unix", base+"-commands.sock")
	if err != nil {
		return nil, nil, err
	}
	defer commands.Close()
	events, err := net.Listen("unix", base+"-events.sock")
	if err != nil {
		return nil, nil, err
	}
	defer events.Close()
	for _, suffix := range []string{"-commands.sock", "-events.sock"} {
		if err = os.Chmod(base+suffix, 0600); err != nil {
			return nil, nil, err
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	err = boundedAuthorization(ctx, func() error {
		return launch(ctx, executable, []string{"-network-helper", base, "-parent-pid", strconv.Itoa(os.Getpid())})
	}, authorizationSlot)
	if err != nil {
		return nil, nil, fmt.Errorf("authorize macOS network helper: %w", err)
	}
	commandConn, err := acceptDarwin(ctx, commands)
	if err != nil {
		return nil, nil, err
	}
	pid, uid, err := darwinPeer(commandConn)
	if err == nil && uid != 0 {
		err = errors.New("network helper is not an administrator process")
	}
	if err == nil {
		err = verifyDarwinPeer(ctx, pid)
	}
	if err != nil {
		commandConn.Close()
		return nil, nil, err
	}
	eventConn, err := acceptDarwin(ctx, events)
	if err != nil {
		commandConn.Close()
		return nil, nil, err
	}
	eventPID, eventUID, err := darwinPeer(eventConn)
	if err != nil || eventPID != pid || eventUID != uid {
		commandConn.Close()
		eventConn.Close()
		return nil, nil, errors.New("private helper channels have different process owners")
	}
	return commandConn, eventConn, nil
}

func darwinSocketOwner(base string) (uint32, error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || filepath.Base(base) != "kone" || !strings.HasPrefix(filepath.Base(filepath.Dir(base)), "kone-helper-") {
		return 0, errors.New("invalid private macOS helper path")
	}
	directory, err := os.Lstat(filepath.Dir(base))
	if err != nil {
		return 0, err
	}
	if !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm() != 0700 {
		return 0, errors.New("private helper directory must be an owned 0700 directory")
	}
	owner, ok := directory.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("private helper directory ownership is unavailable")
	}
	for _, suffix := range []string{"-commands.sock", "-events.sock"} {
		value, err := os.Lstat(base + suffix)
		if err != nil {
			return 0, err
		}
		info, ok := value.Sys().(*syscall.Stat_t)
		if !ok || value.Mode()&os.ModeSocket == 0 || value.Mode().Perm() != 0600 || info.Uid != owner.Uid {
			return 0, errors.New("private helper socket ownership is unverified")
		}
	}
	return owner.Uid, nil
}

func runDarwinNetworkHelper(parent context.Context, base string, parentPID uint32, factory EngineFactory) error {
	if os.Geteuid() != 0 {
		return errors.New("macOS network helper requires administrator authorization")
	}
	if parentPID == 0 {
		return errors.New("invalid private helper parent")
	}
	owner, err := darwinSocketOwner(base)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	dialer := net.Dialer{}
	commands, err := dialer.DialContext(ctx, "unix", base+"-commands.sock")
	if err != nil {
		cancel()
		return err
	}
	events, err := dialer.DialContext(ctx, "unix", base+"-events.sock")
	if err != nil {
		cancel()
		commands.Close()
		return err
	}
	for _, conn := range []net.Conn{commands, events} {
		pid, uid, err := darwinPeer(conn)
		if err != nil || pid != parentPID || uid != owner {
			cancel()
			commands.Close()
			events.Close()
			return errors.New("private helper parent ownership mismatch")
		}
		if err = verifyDarwinPeer(ctx, pid); err != nil {
			cancel()
			commands.Close()
			events.Close()
			return err
		}
	}
	cancel()
	return ServeHelper(parent, commands, events, factory)
}

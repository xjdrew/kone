package desktop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
	"golang.org/x/sys/unix"
)

// The privileged process runs only the shared network RPC service; the Web
// manager and its profile remain owned by the invoking user.
func linuxNewEngine(cfg *kone.KoneConfig, launch LaunchHelper) (*RemoteEngine, error) {
	if launch == nil {
		return nil, errors.New("Linux authorization launcher is unavailable")
	}
	return NewRemote(cfg, func(ctx context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return connectLinux(ctx, launch)
	})
}

func linuxPeer(conn net.Conn) (uint32, uint32, error) {
	value, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("private helper requires a Unix socket")
	}
	raw, err := value.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var peer *unix.Ucred
	var inspectErr error
	if err = raw.Control(func(fd uintptr) { peer, inspectErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, 0, err
	}
	if inspectErr != nil {
		return 0, 0, inspectErr
	}
	if peer.Pid <= 0 {
		return 0, 0, errors.New("Unix peer has no process identity")
	}
	return uint32(peer.Pid), peer.Uid, nil
}

// Only the privileged helper inspects /proc executable identity: ordinary
// users cannot inspect a root process on every Linux procfs configuration.
// The manager trusts root and requires both sockets to belong to the same PID.
func verifyLinuxParent(pid uint32) error {
	if pid == 0 || pid == uint32(os.Getpid()) {
		return errors.New("invalid private helper parent process")
	}
	peer, err := os.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return fmt.Errorf("inspect private helper parent: %w", err)
	}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	if !os.SameFile(peer, self) {
		return errors.New("private helper parent is not the same KONE executable")
	}
	return nil
}

func acceptLinux(ctx context.Context, listener net.Listener) (net.Conn, error) {
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
		return nil, context.Cause(ctx)
	}
}

func connectLinux(parent context.Context, launch LaunchHelper) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
	deadline, stop := context.WithTimeout(parent, 90*time.Second)
	defer stop()
	ctx, cancel := context.WithCancelCause(deadline)
	defer cancel(nil)
	// Use a short socket path in a fresh private directory, independent of TMPDIR.
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
	// pkexec waits for its child to exit. Accept IPC while it runs instead of
	// detaching a root process or invoking a shell. The prompt slot stays owned
	// until pkexec actually exits, including late approvals after cancellation.
	go func() {
		err := boundedAuthorization(ctx, func() error {
			return launch(ctx, executable, []string{"-network-helper", base, "-parent-pid", strconv.Itoa(os.Getpid())})
		}, authorizationSlot)
		if err == nil {
			err = errors.New("Linux network helper exited before connecting")
		}
		cancel(err)
	}()
	commandConn, err := acceptLinux(ctx, commands)
	if err != nil {
		return nil, nil, err
	}
	pid, uid, err := linuxPeer(commandConn)
	if err == nil && uid != 0 {
		err = errors.New("network helper is not an administrator process")
	}
	if err == nil && pid == uint32(os.Getpid()) {
		err = errors.New("network helper must be a separate process")
	}
	if err != nil {
		commandConn.Close()
		return nil, nil, err
	}
	eventConn, err := acceptLinux(ctx, events)
	if err != nil {
		commandConn.Close()
		return nil, nil, err
	}
	eventPID, eventUID, err := linuxPeer(eventConn)
	if err != nil || eventPID != pid || eventUID != uid {
		commandConn.Close()
		eventConn.Close()
		return nil, nil, errors.New("private helper channels have different process owners")
	}
	return commandConn, eventConn, nil
}

func linuxSocketOwner(base string) (uint32, error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || filepath.Base(base) != "kone" || !strings.HasPrefix(filepath.Base(filepath.Dir(base)), "kone-helper-") {
		return 0, errors.New("invalid private Linux helper path")
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

func runLinuxNetworkHelper(parent context.Context, base string, parentPID uint32, factory EngineFactory) error {
	if os.Geteuid() != 0 {
		return errors.New("Linux network helper requires administrator authorization")
	}
	if parentPID == 0 {
		return errors.New("invalid private helper parent")
	}
	owner, err := linuxSocketOwner(base)
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
		pid, uid, err := linuxPeer(conn)
		if err != nil || pid != parentPID || uid != owner {
			cancel()
			commands.Close()
			events.Close()
			return errors.New("private helper parent ownership mismatch")
		}
		if err = verifyLinuxParent(pid); err != nil {
			cancel()
			commands.Close()
			events.Close()
			return err
		}
	}
	cancel()
	return serveProductionHelper(parent, commands, events, factory)
}

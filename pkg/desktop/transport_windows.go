package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/xjdrew/kone/pkg/kone"
	"golang.org/x/sys/windows"
)

type LaunchHelper func(context.Context, string, []string) error

func PrivilegeSeparationAvailable() bool { return true }
func NeedsHelper() bool                  { return !windows.GetCurrentProcessToken().IsElevated() }

func NewEngine(cfg *kone.KoneConfig, launch LaunchHelper) (*RemoteEngine, error) {
	if launch == nil {
		return nil, errors.New("UAC helper launcher is unavailable")
	}
	return NewRemote(cfg, func(ctx context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return connectWindows(ctx, launch)
	})
}

func Preflight(ctx context.Context, cfg *kone.KoneConfig) kone.PreflightReport {
	report := kone.Preflight(ctx, cfg)
	if !NeedsHelper() {
		return report
	}
	report.Ready = true
	for index := range report.Issues {
		issue := &report.Issues[index]
		if issue.Code == "privileges" {
			issue.Severity = "info"
			issue.Message = "Starting capture requires an explicit Windows UAC authorization for the network helper"
		}
		if issue.Severity == "error" {
			report.Ready = false
		}
	}
	return report
}

const pipePrefix = `\\.\pipe\kone-`

func validPipeBase(base string) bool {
	if !strings.HasPrefix(base, pipePrefix) || len(base) != len(pipePrefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(base, pipePrefix))
	return err == nil
}

func peerPID(conn net.Conn, server bool) (uint32, error) {
	file, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("named pipe cannot expose peer identity")
	}
	var pid uint32
	var err error
	if server {
		err = windows.GetNamedPipeServerProcessId(windows.Handle(file.Fd()), &pid)
	} else {
		err = windows.GetNamedPipeClientProcessId(windows.Handle(file.Fd()), &pid)
	}
	return pid, err
}

func verifyPeer(pid uint32, requireElevation bool) error {
	if pid == 0 || pid == uint32(os.Getpid()) {
		return errors.New("invalid IPC peer process")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err = windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil {
		return err
	}
	peer, err := filepath.EvalSymlinks(windows.UTF16ToString(buffer[:size]))
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
	if !strings.EqualFold(filepath.Clean(peer), filepath.Clean(self)) {
		return errors.New("IPC peer is not the same KONE executable")
	}
	if requireElevation {
		var token windows.Token
		if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
			return err
		}
		defer token.Close()
		if !token.IsElevated() {
			return errors.New("network helper is not elevated")
		}
	}
	return nil
}

func acceptPipe(ctx context.Context, listener net.Listener) (net.Conn, error) {
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

func connectWindows(parent context.Context, launch LaunchHelper) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, nil, err
	}
	base := pipePrefix + hex.EncodeToString(random[:])
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	// Protected DACL: current owner and Administrators only. go-winio also
	// rejects remote pipe clients and creates the first instance exclusively.
	config := &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")(A;;GA;;;BA)", InputBufferSize: 65536, OutputBufferSize: 65536}
	commands, err := winio.ListenPipe(base+"-commands", config)
	if err != nil {
		return nil, nil, err
	}
	defer commands.Close()
	events, err := winio.ListenPipe(base+"-events", config)
	if err != nil {
		return nil, nil, err
	}
	defer events.Close()
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	if err = boundedAuthorization(ctx, func() error {
		return launch(ctx, executable, []string{"-network-helper", base, "-parent-pid", strconv.Itoa(os.Getpid())})
	}, authorizationSlot); err != nil {
		return nil, nil, fmt.Errorf("authorize network helper: %w", err)
	}
	commandConn, err := acceptPipe(ctx, commands)
	if err != nil {
		return nil, nil, err
	}
	pid, err := peerPID(commandConn, false)
	if err == nil {
		err = verifyPeer(pid, true)
	}
	if err != nil {
		commandConn.Close()
		return nil, nil, errors.New("network helper identity verification failed")
	}
	eventConn, err := acceptPipe(ctx, events)
	if err != nil {
		commandConn.Close()
		return nil, nil, err
	}
	eventPID, err := peerPID(eventConn, false)
	if err != nil || eventPID != pid {
		commandConn.Close()
		eventConn.Close()
		return nil, nil, errors.New("network helper IPC channels have different owners")
	}
	return commandConn, eventConn, nil
}

// RunNetworkHelper is a private executable mode, not a management listener.
// Both pipe servers must be owned by the expected ordinary KONE process.
func RunNetworkHelper(parent context.Context, base string, parentPID uint32) error {
	return runNetworkHelper(parent, base, parentPID, nil)
}
func runNetworkHelper(parent context.Context, base string, parentPID uint32, factory EngineFactory) error {
	if !validPipeBase(base) || parentPID == 0 {
		return errors.New("invalid private helper invocation")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("network helper requires administrator authorization")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	commands, err := winio.DialPipeContext(ctx, base+"-commands")
	if err != nil {
		cancel()
		return err
	}
	events, err := winio.DialPipeContext(ctx, base+"-events")
	cancel()
	if err != nil {
		commands.Close()
		return err
	}
	for _, conn := range []net.Conn{commands, events} {
		pid, err := peerPID(conn, true)
		if err != nil || pid != parentPID {
			commands.Close()
			events.Close()
			return errors.New("private helper parent identity mismatch")
		}
		if err = verifyPeer(pid, false); err != nil {
			commands.Close()
			events.Close()
			return err
		}
	}
	return ServeHelper(parent, commands, events, factory)
}

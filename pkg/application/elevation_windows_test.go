package application

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWindowsUACHandoff(t *testing.T) {
	config := filepath.Join("config with spaces", "配置.toml")
	wantConfig, err := filepath.Abs(config)
	require.NoError(t, err)
	wantExe, err := os.Executable()
	require.NoError(t, err)
	wantDirectory, err := os.Getwd()
	require.NoError(t, err)
	var output bytes.Buffer
	launched := 0
	handedOff, err := requestWindowsElevation(context.Background(), config, true, &output,
		func() (bool, error) { return false, nil }, func(request elevationRequest) error {
			launched++
			require.Equal(t, wantExe, request.executable)
			require.Equal(t, wantDirectory, request.directory)
			require.Equal(t, []string{"-no-elevate", "-config", wantConfig, "-debug"}, request.args)
			return nil
		})
	require.NoError(t, err)
	require.True(t, handedOff)
	require.Equal(t, 1, launched)
	require.Contains(t, output.String(), "UAC")
	require.Contains(t, output.String(), "Check startup there")
	require.Contains(t, output.String(), "Ctrl+C there")
	t.Run("drive-relative config", func(t *testing.T) {
		relative := filepath.VolumeName(wantDirectory) + "config with spaces.toml"
		absolute, err := filepath.Abs(relative)
		require.NoError(t, err)
		var output bytes.Buffer
		handedOff, err := requestWindowsElevation(context.Background(), relative, false, &output,
			func() (bool, error) { return false, nil }, func(request elevationRequest) error {
				require.Equal(t, []string{"-no-elevate", "-config", absolute}, request.args)
				return nil
			})
		require.NoError(t, err)
		require.True(t, handedOff)
	})
}

func TestWindowsUACDoesNotRetryOrMisreport(t *testing.T) {
	queryFailure := errors.New("token unavailable")
	for _, tc := range []struct {
		name      string
		elevated  bool
		queryErr  error
		launchErr error
		wantErr   error
		wantText  string
		launches  int
	}{
		{"elevated", true, nil, nil, nil, "", 0},
		{"query failed", false, queryFailure, nil, queryFailure, "check Windows process elevation", 0},
		{"cancelled", false, nil, windows.ERROR_CANCELLED, windows.ERROR_CANCELLED, "authorization was cancelled", 1},
		{"denied", false, nil, windows.ERROR_ACCESS_DENIED, windows.ERROR_ACCESS_DENIED, "request Windows administrator permission", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			launches := 0
			handedOff, err := requestWindowsElevation(context.Background(), "config.toml", false, &output,
				func() (bool, error) { return tc.elevated, tc.queryErr }, func(elevationRequest) error {
					launches++
					return tc.launchErr
				})
			require.False(t, handedOff)
			require.Equal(t, tc.launches, launches)
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
				require.ErrorContains(t, err, tc.wantText)
			}
			require.NotContains(t, output.String(), "handed off")
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	handedOff, err := requestWindowsElevation(ctx, "config.toml", false, &output,
		func() (bool, error) { t.Fatal("cancelled before token query"); return false, nil },
		func(elevationRequest) error { t.Fatal("cancelled before UAC"); return nil })
	require.False(t, handedOff)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, output.String())
	t.Run("cancelled during preflight", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var output bytes.Buffer
		handedOff, err := requestWindowsElevation(ctx, "config.toml", false, &output,
			func() (bool, error) { cancel(); return false, nil },
			func(elevationRequest) error { t.Fatal("cancelled before UAC"); return nil })
		require.False(t, handedOff)
		require.ErrorIs(t, err, context.Canceled)
		require.Empty(t, output.String())
	})
}

func TestElevationArgumentsRemainData(t *testing.T) {
	request := elevationRequest{
		executable: `C:\Program Files\KONE\kone.exe`,
		directory:  `C:\配置 path`,
		args:       []string{"-no-elevate", "-config", `C:\配置 path\literal & $(not-a-command) %PATH% "quote"\`, "", "-debug"},
	}
	calls := 0
	err := executeElevation(request, func(info *shellExecuteInfo) error {
		calls++
		wantSize := uint32(112) // Win64 SHELLEXECUTEINFOW ABI.
		if unsafe.Sizeof(uintptr(0)) == 4 {
			wantSize = 60 // Win32 ABI.
		}
		require.Equal(t, wantSize, info.size)
		require.Equal(t, uint32(seeMaskNoAsync), info.mask)
		require.Equal(t, int32(windows.SW_SHOWNORMAL), info.show)
		require.Equal(t, "runas", windows.UTF16PtrToString(info.verb))
		require.Equal(t, request.executable, windows.UTF16PtrToString(info.file))
		require.Equal(t, request.directory, windows.UTF16PtrToString(info.directory))
		// Include argv[0] only for this decoding check. lpParameters itself is
		// escaped as arguments, not ComposeCommandLine's special program name.
		command := windows.EscapeArg(request.executable) + " " + windows.UTF16PtrToString(info.parameters)
		args, err := windows.DecomposeCommandLine(command)
		require.NoError(t, err)
		require.Equal(t, append([]string{request.executable}, request.args...), args)
		require.Zero(t, info.process)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	for _, field := range []string{"executable", "directory", "args"} {
		t.Run("reject NUL in "+field, func(t *testing.T) {
			invalid := request
			switch field {
			case "executable":
				invalid.executable += "\x00"
			case "directory":
				invalid.directory += "\x00"
			case "args":
				invalid.args = []string{"bad\x00argument"}
			}
			require.Error(t, executeElevation(invalid, func(*shellExecuteInfo) error {
				t.Fatal("invalid request must not reach Windows shell")
				return nil
			}))
		})
	}
}

func TestProcessElevationQuery(t *testing.T) {
	elevated, err := processIsElevated()
	require.NoError(t, err)
	require.Equal(t, windows.GetCurrentProcessToken().IsElevated(), elevated)
}

func TestElevatedLaunchDoesNotLoseTerminalProxyPolicy(t *testing.T) {
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy", "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	const secretProxy = "http://user:super-secret@127.0.0.1:7078"
	config := filepath.Join(t.TempDir(), "config.toml")
	write := func(rule string) {
		t.Helper()
		require.NoError(t, os.WriteFile(config, []byte("[[rules]]\ntype='FINAL'\noutbound='"+rule+"'\n"), 0600))
	}
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, secretProxy)
			write(key)
			called := false
			err := launchWithConfiguration(context.Background(), config, elevationRequest{}, func(elevationRequest) error {
				called = true
				return nil
			})
			require.ErrorContains(t, err, "cannot preserve terminal proxy environment")
			require.ErrorContains(t, err, "-no-elevate")
			require.NotContains(t, err.Error(), "super-secret")
			require.False(t, called)
		})
	}
	t.Run("uppercase environment", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", secretProxy)
		write("http_proxy")
		err := launchWithConfiguration(context.Background(), config, elevationRequest{}, func(elevationRequest) error {
			t.Fatal("referenced environment proxy must not be silently changed")
			return nil
		})
		require.ErrorContains(t, err, "cannot preserve terminal proxy environment")
	})
	t.Run("unused environment proxy", func(t *testing.T) {
		t.Setenv("http_proxy", secretProxy)
		write("direct")
		called := false
		require.NoError(t, launchWithConfiguration(context.Background(), config, elevationRequest{}, func(elevationRequest) error {
			called = true
			return nil
		}))
		require.True(t, called)
	})
	t.Run("file changed after parent validation", func(t *testing.T) {
		require.NoError(t, os.WriteFile(config, []byte("unknown=true"), 0600))
		err := launchWithConfiguration(context.Background(), config, elevationRequest{}, func(elevationRequest) error {
			t.Fatal("invalid configuration must not request UAC")
			return nil
		})
		require.ErrorContains(t, err, "revalidate configuration before UAC")
	})
	t.Run("cancelled after configuration validation", func(t *testing.T) {
		write("direct")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := launchWithConfiguration(ctx, config, elevationRequest{}, func(elevationRequest) error {
			t.Fatal("cancelled request must not request UAC")
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestShellExecuteCOMAndResultBoundaries(t *testing.T) {
	changedMode := syscall.Errno(windows.RPC_E_CHANGED_MODE)
	for _, tc := range []struct {
		name    string
		initErr error
		result  uintptr
		lastErr error
		wantErr error
	}{
		{"S_OK", nil, 1, syscall.Errno(0), nil},
		{"S_FALSE", syscall.Errno(1), 1, syscall.Errno(0), nil},
		{"COM initialization failed", changedMode, 0, nil, changedMode},
		{"BOOL failure preserves access denied", nil, 0, windows.ERROR_ACCESS_DENIED, windows.ERROR_ACCESS_DENIED},
		{"BOOL failure preserves cancellation", syscall.Errno(1), 0, windows.ERROR_CANCELLED, windows.ERROR_CANCELLED},
		{"BOOL failure without errno", nil, 0, syscall.Errno(0), windows.ERROR_GEN_FAILURE},
		{"BOOL failure without error", nil, 0, nil, windows.ERROR_GEN_FAILURE},
		{"BOOL success ignores stale errno", nil, 1, windows.ERROR_ACCESS_DENIED, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &shellExecuteInfo{}
			var calls []string
			err := shellExecuteWithCOM(info,
				func() error {
					calls = append(calls, "initialize")
					return tc.initErr
				}, func() {
					calls = append(calls, "uninitialize")
				}, func(received *shellExecuteInfo) (uintptr, error) {
					calls = append(calls, "execute")
					require.Same(t, info, received)
					return tc.result, tc.lastErr
				})
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
			if tc.initErr != nil && tc.initErr != syscall.Errno(1) {
				require.Equal(t, []string{"initialize"}, calls)
				require.ErrorContains(t, err, "initialize Windows shell activation")
			} else {
				require.Equal(t, []string{"initialize", "execute", "uninitialize"}, calls)
			}
		})
	}
}

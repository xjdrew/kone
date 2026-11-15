package application

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
)

func TestLinuxAuthorizationUsesDesktopAgentAndLiteralArguments(t *testing.T) {
	executable := "/tmp/KONE user's build; $(false)"
	args := []string{"-network-helper", "/tmp/kone-helper-owned/kone", "-parent-pid", "1234"}
	command := helperAuthorizationCommand(executable, args)
	require.Equal(t, append([]string{"pkexec", "--disable-internal-agent", executable}, args...), command.Args)
	require.Nil(t, command.Stdin)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, launchManagedHelper(ctx, executable, args), context.Canceled)
}

func TestLinuxAuthorizationFailureCodes(t *testing.T) {
	for _, tc := range []struct{ exit, code string }{
		{"0", ""}, {"126", "authorization_canceled"}, {"127", "authorization_failed"}, {"1", "helper_start_failed"}, {"missing", "authorization_unavailable"},
	} {
		t.Run(tc.exit, func(t *testing.T) {
			directory := t.TempDir()
			if tc.exit != "missing" {
				require.NoError(t, os.WriteFile(filepath.Join(directory, "pkexec"), []byte("#!/bin/sh\nexit "+tc.exit+"\n"), 0700))
			}
			t.Setenv("PATH", directory)
			err := launchManagedHelper(t.Context(), "/unused/kone", nil)
			if tc.code == "" {
				require.NoError(t, err)
				return
			}
			var authorization *desktop.AuthorizationError
			require.True(t, errors.As(err, &authorization))
			require.Equal(t, tc.code, authorization.ErrorCode())
		})
	}
}

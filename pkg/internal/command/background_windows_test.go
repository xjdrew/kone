package command

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackgroundSetsConsoleFlags(t *testing.T) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive")
	Background(cmd)
	require.NotNil(t, cmd.SysProcAttr)
	require.True(t, cmd.SysProcAttr.HideWindow)
	require.Equal(t, createNoWindow, cmd.SysProcAttr.CreationFlags)
}

func TestBackgroundPreservesProcessAttributes(t *testing.T) {
	attributes := &syscall.SysProcAttr{
		CreationFlags:    syscall.CREATE_NEW_PROCESS_GROUP,
		Token:            syscall.Token(123),
		NoInheritHandles: true,
		CmdLine:          "existing command line",
	}
	cmd := exec.Command("unused")
	cmd.SysProcAttr = attributes
	Background(cmd)
	Background(cmd)
	require.Same(t, attributes, cmd.SysProcAttr)
	require.True(t, attributes.HideWindow)
	require.Equal(t, uint32(syscall.CREATE_NEW_PROCESS_GROUP)|createNoWindow, attributes.CreationFlags)
	require.Equal(t, syscall.Token(123), attributes.Token)
	require.True(t, attributes.NoInheritHandles)
	require.Equal(t, "existing command line", attributes.CmdLine)
}

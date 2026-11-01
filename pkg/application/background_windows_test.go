package application

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackgroundChildDoesNotAllocateAConsole(t *testing.T) {
	command := exec.Command("powershell", "-NoProfile", "-NonInteractive")
	prepareBackground(command)
	require.NotNil(t, command.SysProcAttr)
	require.True(t, command.SysProcAttr.HideWindow)
	require.Equal(t, uint32(0x08000000), command.SysProcAttr.CreationFlags)
}

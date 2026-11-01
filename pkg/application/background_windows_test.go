package application

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBrowserChildDoesNotAllocateAConsole(t *testing.T) {
	command := exec.Command("rundll32", "url.dll,FileProtocolHandler", "https://example.invalid/")
	prepareBackground(command)
	require.NotNil(t, command.SysProcAttr)
	require.True(t, command.SysProcAttr.HideWindow)
	require.Equal(t, uint32(0x08000000), command.SysProcAttr.CreationFlags)
}

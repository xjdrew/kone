//go:build !windows

package command

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackgroundPreservesProcessAttributes(t *testing.T) {
	cmd := exec.Command("unused")
	Background(cmd)
	require.Nil(t, cmd.SysProcAttr)
	attributes := &syscall.SysProcAttr{}
	cmd.SysProcAttr = attributes
	Background(cmd)
	require.Same(t, attributes, cmd.SysProcAttr)
}

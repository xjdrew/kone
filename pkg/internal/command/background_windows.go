package command

import (
	"os/exec"
	"syscall"
)

const createNoWindow uint32 = 0x08000000

// Background prevents a noninteractive child from displaying a console window.
// Existing process attributes, including its security token, remain intact.
func Background(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}

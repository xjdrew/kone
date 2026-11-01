package application

import (
	"os/exec"
	"syscall"
)

func prepareBackground(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

//go:build !windows

package command

import "os/exec"

// Background leaves process attributes unchanged on other platforms.
func Background(cmd *exec.Cmd) {}

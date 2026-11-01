//go:build !windows

package application

import "os/exec"

func prepareBackground(*exec.Cmd) {}

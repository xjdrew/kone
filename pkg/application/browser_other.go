//go:build !windows

package application

import (
	"os/exec"
	"runtime"
)

func openBrowser(url string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	command := exec.Command(name, url)
	prepareBackground(command)
	if err := command.Start(); err != nil {
		return err
	}
	go command.Wait()
	return nil
}

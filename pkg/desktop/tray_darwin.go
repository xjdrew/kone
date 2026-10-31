package desktop

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xjdrew/kone/web"
)

// Enable only after native AppKit selector and protocol self-tests pass.
const darwinTrayValidated = false

func TrayAvailable() bool { return darwinTrayValidated }

type trayDiagnostic struct {
	sync.Mutex
	message []byte
}

func (d *trayDiagnostic) Write(data []byte) (int, error) {
	d.Lock()
	defer d.Unlock()
	remaining := 4096 - len(d.message)
	if remaining > len(data) {
		remaining = len(data)
	}
	d.message = append(d.message, data[:remaining]...)
	return len(data), nil
}
func (d *trayDiagnostic) String() string {
	d.Lock()
	defer d.Unlock()
	return strings.Map(func(value rune) rune {
		if value < 32 && value != '\n' && value != '\t' {
			return -1
		}
		return value
	}, string(d.message))
}

func RunTray(ctx context.Context, actions TrayActions) error {
	if ctx.Err() != nil {
		return nil
	}
	if os.Geteuid() == 0 {
		return errors.New("macOS menu bar management must run as an ordinary desktop user")
	}
	command := exec.Command("/usr/bin/osascript", "-l", "JavaScript", "-e", web.MacOSTrayScript)
	input, err := command.StdinPipe()
	if err != nil {
		return err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		return err
	}
	diagnostic := new(trayDiagnostic)
	command.Stderr = diagnostic
	command.WaitDelay = time.Second
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		return err
	}
	return runTrayBridge(ctx, actions, trayProcess{input: input, output: output, wait: command.Wait, kill: command.Process.Kill, diagnostic: diagnostic.String}, 10*time.Second)
}

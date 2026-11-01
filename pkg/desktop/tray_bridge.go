package desktop

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type trayStatus struct {
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	CanStart    bool   `json:"can_start"`
	CanPause    bool   `json:"can_pause"`
	CanDiagnose bool   `json:"can_diagnose"`
}

func nativeTrayStatus(actions TrayActions) trayStatus {
	status := "unknown"
	if actions.State != nil {
		status = actions.State()
	}
	status = strings.Map(func(value rune) rune {
		if value < 32 || value == 127 {
			return -1
		}
		return value
	}, status)
	if len(status) > 128 {
		status = status[:128]
	}
	if status == "" {
		status = "unknown"
	}
	return trayStatus{Status: status, Detail: "KONE — " + status, CanStart: actions.Start != nil && status == "paused", CanPause: actions.Pause != nil && (status == "running" || status == "starting" || status == "degraded"), CanDiagnose: actions.Diagnostics != nil}
}

type trayProcess struct {
	input      io.WriteCloser
	output     io.ReadCloser
	wait       func() error
	kill       func() error
	diagnostic func() string
}

// runTrayBridge accepts only a fixed action vocabulary from the owned ordinary
// UI helper. Credentials, management URLs, configuration and network operations
// never pass through the native process protocol.
func runTrayBridge(parent context.Context, actions TrayActions, process trayProcess, startup time.Duration) (result error) {
	actions = prepareTrayActions(actions)
	ctx, cancel := context.WithCancel(parent)
	events := make(chan string, 8)
	readErrors := make(chan error, 1)
	readerDone := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(events)
		scanner := bufio.NewScanner(process.output)
		scanner.Buffer(make([]byte, 128), 256)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case events <- line:
			case <-ctx.Done():
				return
			}
		}
		readErrors <- scanner.Err()
	}()
	waitDone := make(chan struct{})
	go func() { <-readerDone; process.wait(); close(waitDone) }()
	defer func() {
		cancel()
		process.input.Close()
		select {
		case <-waitDone:
		case <-time.After(2 * time.Second):
			process.kill()
			process.output.Close()
			select {
			case <-waitDone:
			case <-time.After(time.Second):
				result = errors.Join(result, errors.New("native tray helper did not confirm termination"))
			}
		}
		process.output.Close()
		select {
		case <-writerDone:
		case <-time.After(time.Second):
			result = errors.Join(result, errors.New("native tray lifecycle source did not stop"))
		}
	}()
	writeErrors := make(chan error, 1)
	go func() {
		defer close(writerDone)
		encoder := json.NewEncoder(process.input)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := encoder.Encode(nativeTrayStatus(actions)); err != nil {
				select {
				case writeErrors <- err:
				default:
				}
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	if startup <= 0 {
		startup = 10 * time.Second
	}
	readyTimer := time.NewTimer(startup)
	defer readyTimer.Stop()
	ready, exitRequested := false, false
	for {
		select {
		case <-parent.Done():
			return nil
		case <-readyTimer.C:
			if !ready {
				return errors.New("native tray helper did not become ready")
			}
		case <-writeErrors:
			if parent.Err() != nil || exitRequested {
				return nil
			}
			return errors.New("native tray helper stopped accepting lifecycle status")
		case event, open := <-events:
			if parent.Err() != nil {
				return nil
			}
			if !open {
				if parent.Err() != nil || exitRequested {
					return nil
				}
				message := "native tray helper disconnected; browser management remains available"
				if readErr := <-readErrors; readErr != nil {
					message = "native tray helper output exceeded its protocol bounds; browser management remains available"
				}
				if process.diagnostic != nil {
					if detail := strings.TrimSpace(process.diagnostic()); detail != "" {
						message += " (" + detail + ")"
					}
				}
				return errors.New(message)
			}
			if event == "READY" {
				if ready {
					return errors.New("native tray helper repeated its readiness announcement")
				}
				ready = true
				readyTimer.Stop()
				continue
			}
			if !ready {
				return errors.New("native tray helper sent an action before readiness")
			}
			id := uintptr(0)
			switch event {
			case "OPEN":
				id = 1
			case "PAUSE":
				id = 2
			case "EXIT":
				id = 3
				exitRequested = true
			case "START":
				id = 4
			case "DIAGNOSTICS":
				id = 5
			default:
				return fmt.Errorf("native tray helper sent an unknown action")
			}
			invokeTrayAction(actions, id)
		}
	}
}

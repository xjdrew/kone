package kone

import (
	"errors"
	"fmt"
	"net"
)

type captureDeviceIdentity struct {
	name  string
	index int
}

// SetCaptureRecorder installs durable device ownership recording before Run.
// Run stops and rolls back when the recorder fails, before configuring routes.
func (one *One) SetCaptureRecorder(record func(name string, index int) error) error {
	if record == nil {
		return errors.New("capture recorder is nil")
	}
	one.mu.Lock()
	defer one.mu.Unlock()
	if one.started || one.closed {
		return errors.New("capture recorder must be installed before Run")
	}
	one.captureRecorder = record
	return nil
}

func (one *One) recordCaptureDevice(name string) error {
	one.mu.Lock()
	record := one.captureRecorder
	one.mu.Unlock()
	if record == nil {
		return nil
	}
	device, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("inspect created TUN identity: %w", err)
	}
	if device.Index <= 0 {
		return errors.New("created TUN has no verifiable interface index")
	}
	if err := record(device.Name, device.Index); err != nil {
		return fmt.Errorf("persist created TUN identity: %w", err)
	}
	one.mu.Lock()
	one.captureIdentity = captureDeviceIdentity{name: device.Name, index: device.Index}
	one.mu.Unlock()
	return nil
}

// CaptureDeviceIdentity reports the actual created interface, never a requested
// name guessed from configuration. It does not authorize deleting that interface.
func (one *One) CaptureDeviceIdentity() (name string, index int, known bool) {
	one.mu.Lock()
	defer one.mu.Unlock()
	identity := one.captureIdentity
	return identity.name, identity.index, identity.name != "" && identity.index > 0
}

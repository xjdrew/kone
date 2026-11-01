package kone

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCaptureIdentityMustBeRecordedBeforeNetworkConfiguration(t *testing.T) {
	one := &One{}
	require.Error(t, one.SetCaptureRecorder(nil))
	_, _, known := one.CaptureDeviceIdentity()
	require.False(t, known)
	require.NoError(t, one.recordCaptureDevice("unobserved-test-device"), "without recorder fake Network unit tests do not inspect host devices")
	values, err := net.Interfaces()
	require.NoError(t, err)
	if len(values) == 0 {
		t.Skip("no readable local interfaces")
	}
	device := values[0]
	failure := errors.New("durable store full")
	require.NoError(t, one.SetCaptureRecorder(func(string, int) error { return failure }))
	require.ErrorIs(t, one.recordCaptureDevice(device.Name), failure)
	_, _, known = one.CaptureDeviceIdentity()
	require.False(t, known)
	require.NoError(t, one.SetCaptureRecorder(func(name string, index int) error {
		require.Equal(t, device.Name, name)
		require.Equal(t, device.Index, index)
		return nil
	}))
	require.NoError(t, one.recordCaptureDevice(device.Name))
	name, index, known := one.CaptureDeviceIdentity()
	require.True(t, known)
	require.Equal(t, device.Name, name)
	require.Equal(t, device.Index, index)
	require.Error(t, one.recordCaptureDevice("kone-nonexistent-unit-test-interface"))
	one.started = true
	require.Error(t, one.SetCaptureRecorder(func(string, int) error { return nil }))
}

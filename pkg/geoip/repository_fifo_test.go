//go:build linux || darwin

package geoip

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestRepositoryManifestFIFOIsRejectedWithoutWaitingForAWriter(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, unix.Mkfifo(filepath.Join(directory, "manifest.json"), 0600))
	done := make(chan error, 1)
	go func() { _, err := OpenRepository(directory); done <- err }()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "regular file")
	case <-time.After(time.Second):
		t.Fatal("manifest FIFO blocked repository loading")
	}
}

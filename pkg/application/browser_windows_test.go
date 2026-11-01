package application

import (
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWindowsBrowserUsesNativeOpenWithURLAsData(t *testing.T) {
	const target = "http://127.0.0.1:9200/#token=one-use&quoted=%22&literal=中文"
	for _, initialized := range []error{nil, syscall.Errno(1)} {
		opened, released := 0, 0
		err := openBrowserWithShell(target, func(owner windows.Handle, verb, file, args, directory *uint16, show int32) error {
			opened++
			require.Zero(t, owner)
			require.Equal(t, "open", windows.UTF16PtrToString(verb))
			require.Equal(t, target, windows.UTF16PtrToString(file))
			require.Nil(t, args, "URL activation never constructs a shell command line")
			require.Nil(t, directory)
			require.Equal(t, int32(windows.SW_SHOWNORMAL), show)
			return nil
		}, func() error { return initialized }, func() { released++ })
		require.NoError(t, err)
		require.Equal(t, 1, opened)
		require.Equal(t, 1, released)
	}
}

func TestWindowsBrowserPropagatesActivationErrorsAndReleasesCOM(t *testing.T) {
	failed := errors.New("injected shell failure")
	released := 0
	err := openBrowserWithShell("http://127.0.0.1:9200/", func(windows.Handle, *uint16, *uint16, *uint16, *uint16, int32) error { return failed }, func() error { return nil }, func() { released++ })
	require.ErrorIs(t, err, failed)
	require.Equal(t, 1, released)
	err = openBrowserWithShell("http://127.0.0.1:9200/", func(windows.Handle, *uint16, *uint16, *uint16, *uint16, int32) error {
		t.Fatal("failed COM initialization cannot launch a URL")
		return nil
	}, func() error { return failed }, func() { t.Fatal("failed COM initialization is not released") })
	require.ErrorIs(t, err, failed)
	err = openBrowserWithShell("http://127.0.0.1/\x00private", func(windows.Handle, *uint16, *uint16, *uint16, *uint16, int32) error {
		t.Fatal("invalid UTF-16 target cannot launch")
		return nil
	}, func() error { t.Fatal("invalid URL cannot initialize COM"); return nil }, func() {})
	require.Error(t, err)
}

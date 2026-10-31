package tun

import (
	"context"
	"net"
	"runtime"
	"strings"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func listenNetworkNamespace(ctx context.Context, nameOrPath string, config net.ListenConfig, network, address string) (net.Listener, error) {
	return execInNetworkNamespace(nameOrPath, func() (net.Listener, error) {
		return config.Listen(ctx, network, address)
	})
}

type networkNamespaceInterfaceFinder struct {
	control.InterfaceFinder
	options *Options
}

func (f *networkNamespaceInterfaceFinder) Update() error {
	return runInNetworkNamespace(f.options.NetNs, f.InterfaceFinder.Update)
}

func execInNetworkNamespace[T any](nameOrPath string, block func() (T, error)) (T, error) {
	if nameOrPath == "" {
		return block()
	}
	type blockResult struct {
		value T
		err   error
	}
	resultChannel := make(chan blockResult, 1)
	go func() {
		runtime.LockOSThread()
		value, err := execInNetworkNamespaceThread(nameOrPath, block)
		resultChannel <- blockResult{value, err}
	}()
	result := <-resultChannel
	return result.value, result.err
}

func execInNetworkNamespaceThread[T any](nameOrPath string, block func() (T, error)) (T, error) {
	var defaultValue T
	var path string
	if strings.HasPrefix(nameOrPath, "/") {
		path = nameOrPath
	} else {
		path = "/run/netns/" + nameOrPath
	}
	targetFd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return defaultValue, E.Cause(err, "open netns ", nameOrPath)
	}
	defer unix.Close(targetFd)
	err = unix.Setns(targetFd, unix.CLONE_NEWNET)
	if err != nil {
		return defaultValue, E.Cause(err, "set netns to ", nameOrPath)
	}
	return block()
}

func runInNetworkNamespace(nameOrPath string, block func() error) error {
	_, err := execInNetworkNamespace(nameOrPath, func() (struct{}, error) {
		return struct{}{}, block()
	})
	return err
}

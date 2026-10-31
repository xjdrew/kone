//go:build !linux

package tun

import (
	"context"
	"net"
)

func listenNetworkNamespace(ctx context.Context, nameOrPath string, config net.ListenConfig, network, address string) (net.Listener, error) {
	return config.Listen(ctx, network, address)
}

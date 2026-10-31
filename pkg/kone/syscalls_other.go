//go:build !linux && !darwin && !windows

package kone

import (
	"context"
	"errors"
	"net"
)

var errOS = errors.New("unsupported OS")

func (n systemNetwork) Open(context.Context, CoreConfig) (Device, error) { return nil, errOS }
func (n systemNetwork) Configure(context.Context, Device, CoreConfig) (Cleanup, error) {
	return nil, errOS
}
func (n systemNetwork) AddRoute(context.Context, Device, *net.IPNet) (Cleanup, error) {
	return nil, errOS
}
func fixTunIP(ip net.IP) net.IP { return ip }

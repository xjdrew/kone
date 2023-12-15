//
//   date  : 2017-07-14
//   author: xjdrew
//

//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package kone

import (
	"errors"
	"net"
)

var errOS = errors.New("unsupported os")

func initTun(tun string, ipNet *net.IPNet, mtu int) error {
	return errOS
}

func addRoute(tun string, subnet *net.IPNet) error {
	return errOS
}

func fixTunIP(ip net.IP) net.IP {
	return ip
}

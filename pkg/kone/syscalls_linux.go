//
//   date  : 2017-07-14
//   author: xjdrew
//

package kone

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

func execCommand(name, sargs string) error {
	args := strings.Split(sargs, " ")
	cmd := exec.Command(name, args...)
	slog.Info("Executing network command", "command", name, "arguments", sargs)
	return cmd.Run()
}

func initTun(tun string, ipNet *net.IPNet, mtu int) error {
	sargs := fmt.Sprintf("addr add %s dev %s", ipNet, tun)
	if err := execCommand("ip", sargs); err != nil {
		return err
	}

	// brings the link up
	sargs = fmt.Sprintf("link set dev %s up mtu %d qlen 1000", tun, mtu)
	return execCommand("ip", sargs)
}

func addRoute(tun string, subnet *net.IPNet) error {
	sargs := fmt.Sprintf("route add %s dev %s", subnet, tun)
	return execCommand("ip", sargs)
}

func createTun(name string, ip net.IP, mask net.IPMask) (tunDevice, error) {
	ifce, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name},
	})

	if err != nil {
		return nil, err
	}

	slog.Info("TUN device created", "interface", ifce.Name())

	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	if err := initTun(ifce.Name(), ipNet, MTU); err != nil {
		ifce.Close()
		return nil, err
	}
	return ifce, nil
}

func fixTunIP(ip net.IP) net.IP {
	return ip
}

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
	ip := ipNet.IP
	maskIP := net.IP(ipNet.Mask)
	sargs := fmt.Sprintf("%s %s %s mtu %d netmask %s up", tun, ip.String(), ip.String(), mtu, maskIP.String())
	if err := execCommand("ifconfig", sargs); err != nil {
		return err
	}
	return addRoute(tun, ipNet)
}

func addRoute(tun string, subnet *net.IPNet) error {
	ip := subnet.IP
	maskIP := net.IP(subnet.Mask)
	sargs := fmt.Sprintf("-n add -net %s -netmask %s -interface %s", ip.String(), maskIP.String(), tun)
	return execCommand("route", sargs)
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

// can't listen on tun's ip in macosx
func fixTunIP(ip net.IP) net.IP {
	return net.IPv4zero
}

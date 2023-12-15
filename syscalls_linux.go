//
//   date  : 2017-07-14
//   author: xjdrew
//

package kone

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

func execCommand(name, sargs string) error {
	args := strings.Split(sargs, " ")
	cmd := exec.Command(name, args...)
	logger.Infof("exec command: %s %s", name, sargs)
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

func createTun(ip net.IP, mask net.IPMask) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})

	if err != nil {
		return nil, err
	}

	logger.Infof("create %s", ifce.Name())

	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	if err := initTun(ifce.Name(), ipNet, MTU); err != nil {
		return nil, err
	}
	return ifce, nil
}

func fixTunIP(ip net.IP) net.IP {
	return ip
}

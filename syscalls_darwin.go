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

// can't listen on tun's ip in macosx
func fixTunIP(ip net.IP) net.IP {
	return net.IPv4zero
}

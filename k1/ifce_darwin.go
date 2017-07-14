//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

var MTU = 1500

func execCommand(name, sargs string) error {
	args := strings.Split(sargs, " ")
	cmd := exec.Command(name, args...)
	logger.Infof("exec command: %s %s", name, sargs)
	return cmd.Run()
}

func createTun(name string, ip net.IP, mask net.IPMask) (ifce *water.Interface, err error) {
	ifce, err = water.NewTUN(name)
	if err != nil {
		return
	}

	logger.Infof("create %s", ifce.Name())

	// set ip
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
	gw := make(net.IP, len(ip))
	copy(gw, ip)
	gw = gw.To4()
	gw[3]++
	logger.Infof("create %s ip %s gw %s", ifce.Name(), ip, gw)

	sargs := fmt.Sprintf("%s inet %s %s mtu %d", ifce.Name(), ip, gw, MTU)
	err = execCommand("ifconfig", sargs)
	if err != nil {
		return
	}

	logger.Infof("ipNet is %s mtu %d", ipNet, MTU)
	network := ip.Mask(mask)
	sargs = fmt.Sprintf("-n add -net %s %s", network, ip)
	err = execCommand("route", sargs)
	if err != nil {
		return
	}
	return
}

func addRoute(_ string, subnet *net.IPNet, ip net.IP, dstip net.IP) error {
	network := dstip.Mask(subnet.Mask)
	sargs := fmt.Sprintf("-n add -net %s %s", network, ip)
	return execCommand("route", sargs)
}

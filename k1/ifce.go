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

func newTun(name string) (ifce *water.Interface, err error) {
	ifce, err = water.NewTUN(name)
	if err != nil {
		return
	}
	logger.Infof("create %s", ifce.Name())

	sargs := fmt.Sprintf("link set dev %s up mtu %d qlen 1000", ifce.Name(), MTU)
	err = execCommand("ip", sargs)
	if err != nil {
		return
	}
	return
}

func setTunIP(ifce *water.Interface, ip net.IP) error {
	sargs := fmt.Sprintf("addr add dev %s %s", ifce.Name(), ip.String())
	return execCommand("ip", sargs)
}

func setRoute(name string, subnet *net.IPNet) error {
	sargs := fmt.Sprintf("route add %s dev %s", subnet, name)
	return execCommand("ip", sargs)
}

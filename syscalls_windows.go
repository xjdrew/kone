//
//   date  : 2019-08-29
//   author: SUCHMOKUO
//

package kone

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/songgao/water"
	"github.com/thecodeteam/goodbye"
)

var tunNet string

func powershell(args ...string) error {
	cmd := exec.Command("powershell", args...)
	return cmd.Run()
}

func clearRoute(tun string) {
	powershell(
		"Remove-NetRoute",
		"-InterfaceAlias", tun,
		"-Confirm:$false")
}

func addRoute(tun string, subnet *net.IPNet) error {
	tun = fmt.Sprintf(`"%s"`, tun)
	subnetArg := fmt.Sprintf(`"%s"`, subnet.String())
	return powershell(
		"New-NetRoute",
		"-DestinationPrefix", subnetArg,
		"-InterfaceAlias", tun,
		"-PolicyStore", "ActiveStore",
		"-AddressFamily", "IPv4",
		"-NextHop", tunNet)
}

func createTun(ip net.IP, mask net.IPMask) (*water.Interface, error) {
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	s := make([]byte, 4)
	ip4 := ip.To4()
	for i := range s {
		s[i] = ip4[i] & mask[i]
	}
	tunNet = net.IPv4(s[0], s[1], s[2], s[3]).String()

	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     ipNet.String(),
		},
	})

	if err != nil {
		return nil, err
	}

	logger.Infof("initializing %s, please wait...", ifce.Name())

	err = initTun(ifce.Name(), ipNet, MTU)
	if err != nil {
		return nil, err
	}

	logger.Infof("created %s", ifce.Name())
	return ifce, nil
}

func initTun(tun string, ipNet *net.IPNet, mtu int) (err error) {
	tun = fmt.Sprintf(`"%s"`, tun)
	ip := fmt.Sprintf(`"%s"`, ipNet.IP)
	prefix := strings.Split(ipNet.String(), "/")[1]

	// clear previous route.
	clearRoute(tun)

	// clear route on quit.
	goodbye.Notify(context.Background())
	goodbye.Register(func(ctx context.Context, s os.Signal) {
		logger.Infof("clearing route of %s, please wait...", tun)
		clearRoute(tun)
	})

	// set interface mtu and metric.
	err = powershell(
		"Set-NetIPInterface",
		"-InterfaceAlias", tun,
		"-NlMtuBytes", strconv.Itoa(mtu),
		"-InterfaceMetric", "1")

	if err != nil {
		return err
	}

	// remove all previous ips of tun.
	err = powershell(
		"Remove-NetIPAddress",
		"-InterfaceAlias", tun,
		"-AddressFamily", "IPv4",
		"-Confirm:$false")

	if err != nil {
		return err
	}

	// add dns for tun.
	err = powershell(
		"Set-DnsClientServerAddress",
		"-InterfaceAlias", tun,
		"-ServerAddresses", ip)

	if err != nil {
		return err
	}

	// add ip for tun.
	return powershell(
		"New-NetIPAddress",
		"-InterfaceAlias", tun,
		"-IPAddress", ip,
		"-PrefixLength", prefix,
		"-PolicyStore", "ActiveStore",
		"-AddressFamily", "IPv4")
}

func fixTunIP(ip net.IP) net.IP {
	return ip
}

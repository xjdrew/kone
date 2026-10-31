// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.

package dnsconfig

import (
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adapterAddresses returns a list of IP adapter and address
// structures. The structure contains an IP adapter and flattened
// multiple IP addresses including unicast, anycast and multicast
// addresses.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
		if l <= uint32(len(b)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}

func dnsReadDefaultConfig() (conf *DnsConfig) {
	conf = &DnsConfig{
		Ndots:    1,
		Timeout:  5 * time.Second,
		Attempts: 2,
	}
	defer func() {
		if len(conf.Servers) == 0 {
			conf.Servers = defaultNS
		}
	}()
	aas, err := adapterAddresses()
	if err != nil {
		return
	}
	// TODO(bradfitz): this just collects all the DNS servers on all
	// the interfaces in some random order. It should order it by
	// default route, or only use the default route(s) instead.
	// In practice, however, it mostly works.
	for _, aa := range aas {
		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			// Only take interfaces whose OperStatus is IfOperStatusUp(0x01) into DNS configs.
			if aa.OperStatus != windows.IfOperStatusUp {
				continue
			}
			sa, err := dns.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}
			var ip net.IP
			switch sa := sa.(type) {
			case *syscall.SockaddrInet4:
				ip = net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
			case *syscall.SockaddrInet6:
				ip = make(net.IP, net.IPv6len)
				copy(ip, sa.Addr[:])
				if ip[0] == 0xfe && ip[1] == 0xc0 {
					// Ignore these fec0/10 ones. Windows seems to
					// populate them as defaults on its misc rando
					// interfaces.
					continue
				}
			default:
				// Unexpected type.
				continue
			}
			conf.Servers = append(conf.Servers, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return conf
}

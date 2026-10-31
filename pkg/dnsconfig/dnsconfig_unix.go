// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.

//go:build !windows

// Read system DNS config from /etc/resolv.conf

package dnsconfig

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

var (
	DefaultResolvFile = "/etc/resolv.conf"

	getHostname = os.Hostname // variable for testing
)

func dnsReadDefaultConfig() *DnsConfig {
	return dnsReadConfig(DefaultResolvFile)
}

// See resolv.conf(5) on a Linux machine.
func dnsReadConfig(filename string) *DnsConfig {
	conf := &DnsConfig{
		Ndots:    1,
		Timeout:  5 * time.Second,
		Attempts: 2,
	}
	file, err := open(filename)
	if err != nil {
		conf.Servers = defaultNS
		conf.Search = dnsDefaultSearch()
		conf.Err = err
		return conf
	}
	defer file.close()
	if fi, err := file.file.Stat(); err == nil {
		conf.Mtime = fi.ModTime()
	} else {
		conf.Servers = defaultNS
		conf.Search = dnsDefaultSearch()
		conf.Err = err
		return conf
	}
	for line, ok := file.readLine(); ok; line, ok = file.readLine() {
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			continue
		}
		f := getFields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			if len(f) > 1 && len(conf.Servers) < 3 { // small, but the standard limit
				// One more check: make sure server name is
				// just an IP address. Otherwise we need DNS
				// to look it up.
				if _, err := netip.ParseAddr(f[1]); err == nil {
					conf.Servers = append(conf.Servers, net.JoinHostPort(f[1], "53"))
				}
			}

		case "domain": // set search path to just this domain
			if len(f) > 1 {
				conf.Search = []string{ensureRooted(f[1])}
			}

		case "search": // set search path to given servers
			conf.Search = make([]string, 0, len(f)-1)
			for i := 1; i < len(f); i++ {
				name := ensureRooted(f[i])
				if name == "." {
					continue
				}
				conf.Search = append(conf.Search, name)
			}

		case "options": // magic options
			for _, s := range f[1:] {
				switch {
				case hasPrefix(s, "ndots:"):
					n, _, _ := dtoi(s[6:])
					if n < 0 {
						n = 0
					} else if n > 15 {
						n = 15
					}
					conf.Ndots = n
				case hasPrefix(s, "timeout:"):
					n, _, _ := dtoi(s[8:])
					if n < 1 {
						n = 1
					}
					conf.Timeout = time.Duration(n) * time.Second
				case hasPrefix(s, "attempts:"):
					n, _, _ := dtoi(s[9:])
					if n < 1 {
						n = 1
					}
					conf.Attempts = n
				case s == "rotate":
					conf.Rotate = true
				case s == "single-request" || s == "single-request-reopen":
					// Linux option:
					// http://man7.org/linux/man-pages/man5/resolv.conf.5.html
					// "By default, glibc performs IPv4 and IPv6 lookups in parallel [...]
					//  This option disables the behavior and makes glibc
					//  perform the IPv6 and IPv4 requests sequentially."
					conf.SingleRequest = true
				case s == "use-vc" || s == "usevc" || s == "tcp":
					// Linux (use-vc), FreeBSD (usevc) and OpenBSD (tcp) option:
					// http://man7.org/linux/man-pages/man5/resolv.conf.5.html
					// "Sets RES_USEVC in _res.options.
					//  This option forces the use of TCP for DNS resolutions."
					// https://www.freebsd.org/cgi/man.cgi?query=resolv.conf&sektion=5&manpath=freebsd-release-ports
					// https://man.openbsd.org/resolv.conf.5
					conf.UseTCP = true
				case s == "trust-ad":
					conf.TrustAD = true
				case s == "edns0":
					// We use EDNS by default.
					// Ignore this option.
				case s == "no-reload":
					conf.NoReload = true
				default:
					conf.UnknownOpt = true
				}
			}

		case "lookup":
			// OpenBSD option:
			// https://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man5/resolv.conf.5
			// "the legal space-separated values are: bind, file, yp"
			conf.Lookup = f[1:]

		default:
			conf.UnknownOpt = true
		}
	}
	if len(conf.Servers) == 0 {
		conf.Servers = defaultNS
	}
	if len(conf.Search) == 0 {
		conf.Search = dnsDefaultSearch()
	}
	return conf
}

func dnsDefaultSearch() []string {
	hn, err := getHostname()
	if err != nil {
		// best effort
		return nil
	}
	if i := strings.IndexByte(hn, '.'); i >= 0 && i < len(hn)-1 {
		return []string{ensureRooted(hn[i+1:])}
	}
	return nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func ensureRooted(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s
	}
	return s + "."
}

// extend DnsConfig

// avoidDNS reports whether this is a hostname for which we should not
// use DNS. Currently this includes only .onion, per RFC 7686. See
// golang.org/issue/13705. Does not cover .local names (RFC 6762),
// see golang.org/issue/16739.
func avoidDNS(name string) bool {
	if name == "" {
		return true
	}
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return stringsHasSuffixFold(name, ".onion")
}

// nameList returns a list of names for sequential DNS queries.
func (conf *DnsConfig) nameList(name string) []string {
	// Check name length (see isDomainName).
	l := len(name)
	rooted := l > 0 && name[l-1] == '.'
	if l > 254 || l == 254 && !rooted {
		return nil
	}

	// If name is rooted (trailing dot), try only that name.
	if rooted {
		if avoidDNS(name) {
			return nil
		}
		return []string{name}
	}

	hasNdots := strings.Count(name, ".") >= conf.Ndots
	name += "."
	l++

	// Build list of search choices.
	names := make([]string, 0, 1+len(conf.Search))
	// If name has enough dots, try unsuffixed first.
	if hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	// Try suffixes that are not too long (see isDomainName).
	for _, suffix := range conf.Search {
		fqdn := name + suffix
		if !avoidDNS(fqdn) && len(fqdn) <= 254 {
			names = append(names, fqdn)
		}
	}
	// Try unsuffixed, if not tried first above.
	if !hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	return names
}

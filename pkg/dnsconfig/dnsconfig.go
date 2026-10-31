// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.

package dnsconfig

import (
	"time"
)

var (
	defaultNS = []string{"127.0.0.1:53", "[::1]:53"}
)

type DnsConfig struct {
	Servers    []string      // server addresses (in host:port form) to use
	Search     []string      // rooted suffixes to append to local name
	Ndots      int           // number of dots in name to trigger absolute lookup
	Timeout    time.Duration // wait before giving up on a query, including retries
	Attempts   int           // lost packets before giving up on server
	Rotate     bool          // round robin among servers
	UnknownOpt bool          // anything unknown was encountered
	Lookup     []string      // OpenBSD top-level database "lookup" order
	Err        error         // any error that occurs during open of resolv.conf
	Mtime      time.Time     // time of resolv.conf modification

	SingleRequest bool // use sequential A and AAAA queries instead of parallel queries
	UseTCP        bool // force usage of TCP for DNS resolutions
	TrustAD       bool // add AD flag to queries
	NoReload      bool // do not check for config file updates
}

func ReadDnsConfig() *DnsConfig {
	return dnsReadDefaultConfig()
}

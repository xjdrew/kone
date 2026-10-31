// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.

//go:build !windows

package dnsconfig

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var dnsReadConfigTests = []struct {
	name string
	want *DnsConfig
}{
	{
		name: "testdata/resolv.conf",
		want: &DnsConfig{
			Servers:    []string{"8.8.8.8:53", "[2001:4860:4860::8888]:53", "[fe80::1%lo0]:53"},
			Search:     []string{"localdomain."},
			Ndots:      5,
			Timeout:    10 * time.Second,
			Attempts:   3,
			Rotate:     true,
			UnknownOpt: true, // the "options attempts 3" line
		},
	},
	{
		name: "testdata/domain-resolv.conf",
		want: &DnsConfig{
			Servers:  []string{"8.8.8.8:53"},
			Search:   []string{"localdomain."},
			Ndots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
		},
	},
	{
		name: "testdata/search-resolv.conf",
		want: &DnsConfig{
			Servers:  []string{"8.8.8.8:53"},
			Search:   []string{"test.", "invalid."},
			Ndots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
		},
	},
	{
		name: "testdata/search-single-dot-resolv.conf",
		want: &DnsConfig{
			Servers:  []string{"8.8.8.8:53"},
			Search:   []string{},
			Ndots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
		},
	},
	{
		name: "testdata/empty-resolv.conf",
		want: &DnsConfig{
			Servers:  defaultNS,
			Ndots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/invalid-ndots-resolv.conf",
		want: &DnsConfig{
			Servers:  defaultNS,
			Ndots:    0,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/large-ndots-resolv.conf",
		want: &DnsConfig{
			Servers:  defaultNS,
			Ndots:    15,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/negative-ndots-resolv.conf",
		want: &DnsConfig{
			Servers:  defaultNS,
			Ndots:    0,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/openbsd-resolv.conf",
		want: &DnsConfig{
			Ndots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Lookup:   []string{"file", "bind"},
			Servers:  []string{"169.254.169.254:53", "10.240.0.1:53"},
			Search:   []string{"c.symbolic-datum-552.internal."},
		},
	},
	{
		name: "testdata/single-request-resolv.conf",
		want: &DnsConfig{
			Servers:       defaultNS,
			Ndots:         1,
			SingleRequest: true,
			Timeout:       5 * time.Second,
			Attempts:      2,
			Search:        []string{"domain.local."},
		},
	},
	{
		name: "testdata/single-request-reopen-resolv.conf",
		want: &DnsConfig{
			Servers:       defaultNS,
			Ndots:         1,
			SingleRequest: true,
			Timeout:       5 * time.Second,
			Attempts:      2,
			Search:        []string{"domain.local."},
		},
	},
	{
		name: "testdata/linux-use-vc-resolv.conf",
		want: &DnsConfig{
			Servers:  defaultNS,
			Ndots:    1,
			UseTCP:   true,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/freebsd-usevc-resolv.conf",
		want: &DnsConfig{
			Servers:  defaultNS,
			Ndots:    1,
			UseTCP:   true,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/openbsd-tcp-resolv.conf",
		want: &DnsConfig{
			Servers:  defaultNS,
			Ndots:    1,
			UseTCP:   true,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
}

func TestDNSReadConfig(t *testing.T) {
	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()
	getHostname = func() (string, error) { return "host.domain.local", nil }

	for _, tt := range dnsReadConfigTests {
		want := *tt.want
		if len(want.Search) == 0 {
			want.Search = dnsDefaultSearch()
		}
		conf := dnsReadConfig(tt.name)
		if conf.Err != nil {
			t.Fatal(conf.Err)
		}
		conf.Mtime = time.Time{}
		if !reflect.DeepEqual(conf, &want) {
			t.Errorf("%s:\ngot: %+v\nwant: %+v", tt.name, conf, want)
		}
	}
}

func TestDNSReadMissingFile(t *testing.T) {
	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()
	getHostname = func() (string, error) { return "host.domain.local", nil }

	conf := dnsReadConfig("a-nonexistent-file")
	if !os.IsNotExist(conf.Err) {
		t.Errorf("missing resolv.conf:\ngot: %v\nwant: %v", conf.Err, fs.ErrNotExist)
	}
	conf.Err = nil
	want := &DnsConfig{
		Servers:  defaultNS,
		Ndots:    1,
		Timeout:  5 * time.Second,
		Attempts: 2,
		Search:   []string{"domain.local."},
	}
	if !reflect.DeepEqual(conf, want) {
		t.Errorf("missing resolv.conf:\ngot: %+v\nwant: %+v", conf, want)
	}
}

var dnsDefaultSearchTests = []struct {
	name string
	err  error
	want []string
}{
	{
		name: "host.long.domain.local",
		want: []string{"long.domain.local."},
	},
	{
		name: "host.local",
		want: []string{"local."},
	},
	{
		name: "host",
		want: nil,
	},
	{
		name: "host.domain.local",
		err:  errors.New("errored"),
		want: nil,
	},
	{
		// ensures we don't return []string{""}
		// which causes duplicate lookups
		name: "foo.",
		want: nil,
	},
}

func TestDNSDefaultSearch(t *testing.T) {
	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()

	for _, tt := range dnsDefaultSearchTests {
		getHostname = func() (string, error) { return tt.name, tt.err }
		got := dnsDefaultSearch()
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("dnsDefaultSearch with hostname %q and error %+v = %q, wanted %q", tt.name, tt.err, got, tt.want)
		}
	}
}

func TestDNSNameLength(t *testing.T) {
	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()
	getHostname = func() (string, error) { return "host.domain.local", nil }

	var char63 = ""
	for i := 0; i < 63; i++ {
		char63 += "a"
	}
	longDomain := strings.Repeat(char63+".", 5) + "example"

	for _, tt := range dnsReadConfigTests {
		conf := dnsReadConfig(tt.name)
		if conf.Err != nil {
			t.Fatal(conf.Err)
		}

		suffixList := tt.want.Search
		if len(suffixList) == 0 {
			suffixList = dnsDefaultSearch()
		}

		var shortestSuffix int
		for _, suffix := range suffixList {
			if shortestSuffix == 0 || len(suffix) < shortestSuffix {
				shortestSuffix = len(suffix)
			}
		}

		// Test a name that will be maximally long when prefixing the shortest
		// suffix (accounting for the intervening dot).
		longName := longDomain[len(longDomain)-254+1+shortestSuffix:]
		if longName[0] == '.' || longName[1] == '.' {
			longName = "aa." + longName[3:]
		}
		for _, fqdn := range conf.nameList(longName) {
			if len(fqdn) > 254 {
				t.Errorf("got %d; want less than or equal to 254", len(fqdn))
			}
		}

		// Now test a name that's too long for suffixing.
		unsuffixable := "a." + longName[1:]
		unsuffixableResults := conf.nameList(unsuffixable)
		if len(unsuffixableResults) != 1 {
			t.Errorf("suffixed names %v; want []", unsuffixableResults[1:])
		}

		// Now test a name that's too long for DNS.
		tooLong := "a." + longDomain
		tooLongResults := conf.nameList(tooLong)
		if tooLongResults != nil {
			t.Errorf("suffixed names %v; want nil", tooLongResults)
		}
	}
}

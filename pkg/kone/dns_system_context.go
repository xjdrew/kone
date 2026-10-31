package kone

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/xjdrew/kone/pkg/dnsconfig"
)

type DNSSystemScope struct {
	Suffix      string   `json:"suffix"`
	Servers     []string `json:"servers"`
	Interface   string   `json:"interface,omitempty"`
	Exact       bool     `json:"exact,omitempty"`
	Unavailable bool     `json:"unavailable,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// DNSSystemContext is an observed, read-only startup snapshot. It is never
// persisted as user configuration and does not claim complete VPN semantics.
type DNSSystemContext struct {
	Source         string           `json:"source"`
	DefaultServers []string         `json:"default_servers"`
	StubServers    []string         `json:"stub_servers,omitempty"`
	SearchDomains  []string         `json:"search_domains"`
	Scopes         []DNSSystemScope `json:"scopes"`
	Warnings       []string         `json:"warnings"`
	UseTCP         bool             `json:"use_tcp"`
	RequireManual  bool             `json:"require_manual"`
}

func dnsRouteKey(route DNSRouteConfig) string {
	key := normalizeDNSSuffix(route.Suffix)
	if route.Automatic {
		key += "|system"
	}
	if route.Exact {
		key += "|exact"
	}
	return key
}

func cloneDNSSystemContext(value DNSSystemContext) DNSSystemContext {
	value.DefaultServers = append([]string(nil), value.DefaultServers...)
	value.StubServers = append([]string(nil), value.StubServers...)
	value.SearchDomains = append([]string(nil), value.SearchDomains...)
	value.Warnings = append([]string(nil), value.Warnings...)
	value.Scopes = append([]DNSSystemScope(nil), value.Scopes...)
	for i := range value.Scopes {
		value.Scopes[i].Servers = append([]string(nil), value.Scopes[i].Servers...)
	}
	return value
}

func mergeSystemDNSContext(cfg DNSConfig, observed DNSSystemContext, discoveryErr error) DNSConfig {
	observed = cloneDNSSystemContext(observed)
	if !cfg.System && len(observed.StubServers) > 0 {
		observed.RequireManual = false
	}
	if len(observed.SearchDomains) > 32 {
		observed.SearchDomains = observed.SearchDomains[:32]
	}
	if discoveryErr != nil {
		observed.Warnings = append(observed.Warnings, "System DNS scope discovery is incomplete; configure explicit dns.rules for private/VPN names")
	}
	if len(observed.Warnings) > 16 {
		observed.Warnings = observed.Warnings[:16]
	}
	cfg.Rules = append([]DNSRouteConfig(nil), cfg.Rules...)
	if len(cfg.Rules) >= 64 && len(observed.Scopes) > 0 {
		observed.RequireManual = true
		observed.Warnings = append(observed.Warnings, "DNS rule capacity leaves no room to protect system scopes; set explicit DNS servers/rules")
		cfg.SystemContext = observed
		return cfg
	}
	for _, scope := range observed.Scopes {
		if !validDNSSuffix(normalizeDNSSuffix(scope.Suffix)) {
			continue
		}
		route := DNSRouteConfig{Suffix: normalizeDNSSuffix(scope.Suffix), Servers: append([]string(nil), scope.Servers...), Interface: scope.Interface, Automatic: true, Exact: scope.Exact, Unavailable: scope.Unavailable, Reason: scope.Reason}
		if len(observed.StubServers) > 0 && !cfg.System {
			route.Servers = append([]string(nil), observed.StubServers...)
			route.Interface = ""
			route.Unavailable, route.Reason = false, ""
		}
		if len(route.Servers) == 0 {
			route.Unavailable = true
			route.Reason = "system DNS scope has no usable upstream"
		}
		if cfg.System {
			for _, server := range route.Servers {
				host, _, _ := net.SplitHostPort(server)
				if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
					route.Unavailable = true
					route.Reason = "system DNS capture cannot use an unverified loopback scope resolver"
				}
			}
		}
		if route.Unavailable && len(observed.Warnings) < 16 {
			observed.Warnings = append(observed.Warnings, "System DNS scope "+route.Suffix+" is unavailable; configure dns.rules explicitly")
		}
		duplicate := -1
		for i, existing := range cfg.Rules {
			if existing.Automatic && dnsRouteKey(existing) == dnsRouteKey(route) {
				duplicate = i
				break
			}
		}
		if duplicate >= 0 {
			existing := cfg.Rules[duplicate]
			if route.Unavailable {
				cfg.Rules[duplicate].Unavailable = true
				cfg.Rules[duplicate].Reason = route.Reason
			}
			if existing.Interface != route.Interface || strings.Join(existing.Servers, "|") != strings.Join(route.Servers, "|") {
				cfg.Rules[duplicate].Unavailable = true
				cfg.Rules[duplicate].Reason = "ambiguous system DNS scope; configure dns.rules explicitly"
			}
			continue
		}
		if len(cfg.Rules) >= 63 {
			cfg.Rules = append(cfg.Rules, DNSRouteConfig{Suffix: ".", Automatic: true, Unavailable: true, Reason: "system DNS scope limit exceeded; configure dns.rules explicitly"})
			observed.Warnings = append(observed.Warnings, "System DNS scope limit exceeded; unmatched automatic queries are refused")
			break
		}
		cfg.Rules = append(cfg.Rules, route)
	}
	if cfg.System && len(observed.StubServers) > 0 {
		var realServers []string
		for _, server := range observed.DefaultServers {
			host, _, _ := net.SplitHostPort(server)
			if ip, err := netip.ParseAddr(host); err == nil && !ip.IsLoopback() {
				realServers = append(realServers, server)
			}
		}
		if len(realServers) == 0 {
			observed.RequireManual = true
			observed.Warnings = append(observed.Warnings, "System DNS capture requires real upstreams; the system stub would recurse")
		} else {
			cfg.Servers = realServers
		}
	}
	cfg.SystemContext = observed
	return cfg
}

type dnsLimitedOutput struct{ bytes.Buffer }

func (b *dnsLimitedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 1<<20 {
		return 0, errors.New("system DNS discovery output exceeds limit")
	}
	return b.Buffer.Write(data)
}

func readDNSCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.WaitDelay = time.Second
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "LC_ALL=") && !strings.HasPrefix(entry, "LANG=") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "LC_ALL=C", "LANG=C")
	var output dnsLimitedOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("read-only system DNS discovery command failed")
	}
	return output.Bytes(), nil
}

func readDNSSystemContext() (DNSSystemContext, error) {
	return readDNSSystemContextFor(runtime.GOOS, dnsconfig.ReadDnsConfig(), readDNSCommand)
}

func readDNSSystemContextFor(platform string, base *dnsconfig.DnsConfig, read func(context.Context, string, ...string) ([]byte, error)) (DNSSystemContext, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if base == nil {
		base = &dnsconfig.DnsConfig{}
	}
	observed := DNSSystemContext{Source: platform, SearchDomains: append([]string(nil), base.Search...), UseTCP: base.UseTCP}
	switch platform {
	case "linux":
		for _, server := range base.Servers {
			if server == "127.0.0.53:53" || server == "127.0.0.54:53" {
				observed.StubServers = append(observed.StubServers, server)
			}
		}
		domains, err := read(ctx, "resolvectl", "domain")
		if err != nil {
			return observed, err
		}
		servers, serversErr := read(ctx, "resolvectl", "dns")
		tls, tlsErr := read(ctx, "resolvectl", "dnsovertls")
		defaults, defaultsErr := read(ctx, "resolvectl", "default-route")
		parsed := parseResolvedDNSContext(servers, domains, tls, defaults)
		parsed.StubServers = observed.StubServers
		parsed.SearchDomains = append(parsed.SearchDomains, observed.SearchDomains...)
		parsed.UseTCP = observed.UseTCP
		return parsed, errors.Join(serversErr, tlsErr, defaultsErr)
	case "windows":
		data, err := read(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", windowsDNSContextScript)
		if err != nil {
			return observed, err
		}
		return parseWindowsDNSContext(data)
	case "darwin":
		data, err := read(ctx, "scutil", "--dns")
		if err != nil {
			return observed, err
		}
		return parseDarwinDNSContext(data)
	}
	return observed, errors.New("system DNS context discovery is unavailable on this platform")
}

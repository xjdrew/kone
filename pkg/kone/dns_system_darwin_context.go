package kone

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"strings"
)

func parseDarwinDNSContext(data []byte) (DNSSystemContext, error) {
	return parseDarwinDNSContextExcluding(data, nil)
}

func parseDarwinDNSContextExcluding(data []byte, excluded map[string]bool) (DNSSystemContext, error) {
	context := DNSSystemContext{Source: "macos-scutil", SearchDomains: []string{}, Scopes: []DNSSystemScope{}, Warnings: []string{}}
	if len(data) > 1<<20 {
		return context, errors.New("macOS DNS context exceeds output limit")
	}
	type resolver struct {
		domain, device, options, port, order string
		servers, search                      []string
		scoped                               bool
	}
	var current *resolver
	var resolvers []resolver
	finish := func() {
		if current != nil {
			resolvers = append(resolvers, *current)
			current = nil
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "resolver #") {
			finish()
			current = &resolver{}
			if len(resolvers) >= 128 {
				context.RequireManual = true
				break
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "domain":
			current.domain = normalizeDNSSuffix(value)
		case strings.HasPrefix(key, "search domain["):
			if len(current.search) < 32 {
				current.search = append(current.search, normalizeDNSSuffix(value))
			}
		case strings.HasPrefix(key, "nameserver["):
			if len(current.servers) < 17 {
				current.servers = append(current.servers, value)
			}
		case key == "if_index":
			start, end := strings.Index(value, "("), strings.Index(value, ")")
			if start >= 0 && end > start {
				current.device = value[start+1 : end]
			}
		case key == "flags":
			current.scoped = strings.Contains(strings.ToLower(value), "scoped")
		case key == "options":
			current.options = value
		case key == "port":
			current.port = value
		case key == "order":
			current.order = value
		}
	}
	finish()
	if err := scanner.Err(); err != nil {
		return context, errors.New("macOS DNS context contains oversized lines")
	}
	var defaultOrder uint64 = 1 << 32
	var defaultServers []string
	defaultUnusable, defaultAmbiguous, unknownDefaultOrder := false, false, false
	for _, resolver := range resolvers {
		portValid := resolver.port == "" || validatePort(resolver.port) == nil
		if resolver.port != "" && portValid {
			for i, server := range resolver.servers {
				if address, err := normalizeDNSServer(server); err == nil {
					host, _, _ := net.SplitHostPort(address)
					resolver.servers[i] = net.JoinHostPort(host, resolver.port)
				}
			}
		}
		servers, valid := normalizedSystemServers(resolver.servers)
		owned := len(servers) > 0 && valid && portValid
		for _, server := range servers {
			owned = owned && excluded[server]
		}
		if owned {
			continue
		}
		for _, suffix := range resolver.search {
			if validDNSSuffix(suffix) && !containsDNSValue(context.SearchDomains, suffix) && len(context.SearchDomains) < 32 {
				context.SearchDomains = append(context.SearchDomains, suffix)
			}
		}
		suffixes := []string{}
		if !resolver.scoped && (resolver.domain == "" || resolver.domain == ".") {
			// Apple SearchOrder, rather than scutil's display position, chooses
			// between the ordinary default and match-all supplemental resolvers.
			order := uint64(200000)
			if resolver.order != "" {
				var err error
				order, err = strconv.ParseUint(resolver.order, 10, 32)
				if err != nil {
					unknownDefaultOrder = true
					continue
				}
			}
			unusable := !valid || !portValid || len(servers) == 0 || resolver.options != ""
			if order < defaultOrder {
				defaultOrder = order
				defaultServers = append([]string(nil), servers...)
				defaultUnusable, defaultAmbiguous = unusable, false
			} else if order == defaultOrder {
				defaultUnusable = defaultUnusable || unusable
				defaultAmbiguous = defaultAmbiguous || strings.Join(defaultServers, "|") != strings.Join(servers, "|")
			}
		} else if resolver.domain != "" {
			suffixes = append(suffixes, resolver.domain)
		} else if resolver.scoped {
			suffixes = append(suffixes, resolver.search...)
		}
		for _, suffix := range suffixes {
			if !validDNSSuffix(suffix) {
				context.RequireManual = true
				context.Warnings = append(context.Warnings, "A macOS resolver domain could not be represented; configure ASCII/punycode DNS rules")
				continue
			}
			scope := DNSSystemScope{Suffix: suffix, Servers: servers, Interface: resolver.device}
			if !valid || !portValid || len(servers) == 0 || resolver.options != "" || resolver.scoped && resolver.device == "" {
				scope.Unavailable = true
				scope.Reason = "macOS scoped/multicast/encrypted resolver needs explicit DNS configuration"
			}
			context.Scopes = append(context.Scopes, scope)
		}
	}
	if defaultUnusable || defaultAmbiguous || unknownDefaultOrder {
		context.RequireManual = true
		context.Warnings = append(context.Warnings, "macOS default resolver order or transport is ambiguous; configure explicit DNS servers")
	} else {
		context.DefaultServers = defaultServers
	}
	if len(resolvers) == 0 {
		return context, errors.New("macOS DNS context contains no resolvers")
	}
	return context, nil
}

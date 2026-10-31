package kone

import (
	"bufio"
	"regexp"
	"sort"
	"strings"
)

var resolvedLinkLine = regexp.MustCompile(`^Link\s+[0-9]+\s+\(([^)]+)\):\s*(.*)$`)

func parseResolvedLinks(data []byte) map[string][]string {
	result := map[string][]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Global:") {
			result[""] = strings.Fields(strings.TrimPrefix(line, "Global:"))
			continue
		}
		if match := resolvedLinkLine.FindStringSubmatch(line); len(match) == 3 && len(result) < 128 {
			result[match[1]] = strings.Fields(match[2])
		}
	}
	return result
}

func normalizedSystemServers(servers []string) ([]string, bool) {
	result := []string{}
	valid := true
	for _, server := range servers {
		if len(result) >= 16 {
			valid = false
			break
		}
		value, err := normalizeDNSServer(server)
		if err != nil {
			valid = false
			continue
		}
		if !containsDNSValue(result, value) {
			result = append(result, value)
		}
	}
	return result, valid
}

func containsDNSValue(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func parseResolvedDNSContext(dnsData, domainData, tlsData, defaultData []byte) DNSSystemContext {
	servers := parseResolvedLinks(dnsData)
	domains := parseResolvedLinks(domainData)
	tls := parseResolvedLinks(tlsData)
	defaults := parseResolvedLinks(defaultData)
	context := DNSSystemContext{Source: "systemd-resolved", SearchDomains: []string{}, Scopes: []DNSSystemScope{}, Warnings: []string{}}
	keys := make([]string, 0, len(domains))
	for key := range domains {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, device := range keys {
		values, valid := normalizedSystemServers(servers[device])
		for _, domain := range domains[device] {
			routing := strings.HasPrefix(domain, "~")
			suffix := normalizeDNSSuffix(strings.TrimPrefix(domain, "~"))
			if !validDNSSuffix(suffix) {
				context.RequireManual = true
				context.Warnings = append(context.Warnings, "A systemd-resolved domain could not be represented; configure ASCII/punycode DNS rules")
				continue
			}
			if !routing && !containsDNSValue(context.SearchDomains, suffix) {
				context.SearchDomains = append(context.SearchDomains, suffix)
			}
			scope := DNSSystemScope{Suffix: suffix, Servers: append([]string(nil), values...), Interface: device}
			security := strings.Join(tls[device], "")
			if security == "" {
				security = strings.Join(tls[""], "")
			}
			if !valid || len(values) == 0 {
				scope.Unavailable = true
				scope.Reason = "systemd-resolved scope has missing or unsupported DNS servers"
			} else if security != "no" {
				scope.Unavailable = true
				scope.Reason = "systemd-resolved encrypted or unknown DNS transport requires system stub or explicit configuration"
			}
			context.Scopes = append(context.Scopes, scope)
			if len(context.Scopes) > 64 {
				context.Warnings = append(context.Warnings, "System DNS context exceeds supported scope count")
				return context
			}
		}
	}
	for device, raw := range servers {
		isDefault := device == "" || containsDNSValue(defaults[device], "yes") || containsDNSValue(domains[device], "~.")
		if !isDefault {
			continue
		}
		security := strings.Join(tls[device], "")
		if security == "" {
			security = strings.Join(tls[""], "")
		}
		if security != "no" {
			continue
		}
		values, valid := normalizedSystemServers(raw)
		if !valid {
			continue
		}
		for _, server := range values {
			if !containsDNSValue(context.DefaultServers, server) && len(context.DefaultServers) < 16 {
				context.DefaultServers = append(context.DefaultServers, server)
			}
		}
	}
	if len(domains) == 0 {
		context.Warnings = append(context.Warnings, "systemd-resolved returned no recognizable per-link DNS context")
	}
	return context
}

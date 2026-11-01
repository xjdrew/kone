package kone

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
)

const windowsDNSContextScript = `$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8;
$dns=@(Get-DnsClientServerAddress); $links=@(Get-DnsClient | Select-Object -First 129 | ForEach-Object { $c=$_; [pscustomobject]@{name=$c.InterfaceAlias;index=$c.InterfaceIndex;suffix=$c.ConnectionSpecificSuffix;servers=@($dns|Where-Object InterfaceIndex -eq $c.InterfaceIndex|ForEach-Object {$_.ServerAddresses})} });
$nrpt=@(Get-DnsClientNrptPolicy -Effective | Select-Object -First 65 | ForEach-Object { [pscustomobject]@{namespaces=@($_.Namespace);servers=@(($_.NameServers -join ',') -split '[,; ]+' | Where-Object {$_});secure=[bool]($_.DirectAccessEnabled -or $_.DnsSecValidationRequired -or $_.DnsSecQueryIPsecRequired -or $_.DirectAccessQueryIPsecRequired);query_policy=[string]$_.QueryPolicy} });
$ifaces=@(Get-NetIPInterface); $routes=@(Get-NetRoute | Select-Object -First 4097 | ForEach-Object { $r=$_; $i=$ifaces|Where-Object { $_.InterfaceIndex -eq $r.InterfaceIndex -and $_.AddressFamily -eq $r.AddressFamily }|Select-Object -First 1; [pscustomobject]@{prefix=$r.DestinationPrefix;interface=$r.InterfaceAlias;metric=([long]$r.RouteMetric+[long]$i.InterfaceMetric)} });
[pscustomobject]@{links=$links;nrpt=$nrpt;routes=$routes;search=@((Get-DnsClientGlobalSetting).SuffixSearchList)} | ConvertTo-Json -Depth 7 -Compress`

type windowsDNSContext struct {
	Links []struct {
		Name    string   `json:"name"`
		Index   int      `json:"index"`
		Suffix  string   `json:"suffix"`
		Servers []string `json:"servers"`
	} `json:"links"`
	NRPT []struct {
		Namespaces  []string `json:"namespaces"`
		Servers     []string `json:"servers"`
		Secure      bool     `json:"secure"`
		QueryPolicy string   `json:"query_policy"`
	} `json:"nrpt"`
	Routes []struct {
		Prefix    string `json:"prefix"`
		Interface string `json:"interface"`
		Metric    int    `json:"metric"`
	} `json:"routes"`
	Search []string `json:"search"`
}

func windowsDNSScopeInterface(data windowsDNSContext, servers []string) (string, bool) {
	selected := ""
	for _, server := range servers {
		host, _, _ := net.SplitHostPort(server)
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return "", false
		}
		bestBits, bestMetric := -1, int(^uint(0)>>1)
		device := ""
		ambiguous := false
		for _, route := range data.Routes {
			prefix, err := netip.ParsePrefix(route.Prefix)
			if err != nil || route.Metric < 0 || route.Metric > 1<<30 || !prefix.Contains(ip.WithZone("").Unmap()) {
				continue
			}
			if prefix.Bits() > bestBits || prefix.Bits() == bestBits && route.Metric < bestMetric {
				bestBits, bestMetric, device, ambiguous = prefix.Bits(), route.Metric, route.Interface, false
			} else if prefix.Bits() == bestBits && route.Metric == bestMetric && route.Interface != device {
				ambiguous = true
			}
		}
		if device == "" {
			for _, link := range data.Links {
				values, _ := normalizedSystemServers(link.Servers)
				if containsDNSValue(values, server) {
					if device != "" && device != link.Name {
						ambiguous = true
					}
					device = link.Name
				}
			}
		}
		if device == "" || ambiguous || selected != "" && selected != device {
			return "", false
		}
		selected = device
	}
	return selected, selected != ""
}

func parseWindowsDNSContext(raw []byte) (DNSSystemContext, error) {
	context := DNSSystemContext{Source: "windows-nrpt-and-adapters", SearchDomains: []string{}, Scopes: []DNSSystemScope{}, Warnings: []string{}}
	if len(raw) > 1<<20 {
		return context, errors.New("Windows DNS context exceeds output limit")
	}
	var data windowsDNSContext
	if err := json.Unmarshal(raw, &data); err != nil {
		return context, errors.New("invalid Windows DNS context JSON")
	}
	if len(data.Links) > 128 || len(data.NRPT) > 64 || len(data.Routes) > 4096 {
		context.RequireManual = true
		context.Warnings = append(context.Warnings, "Windows DNS context exceeds discovery limits; configure explicit DNS settings")
		return context, nil
	}
	for _, domain := range data.Search {
		suffix := normalizeDNSSuffix(domain)
		if validDNSSuffix(suffix) && len(context.SearchDomains) < 32 {
			context.SearchDomains = append(context.SearchDomains, suffix)
		}
	}
	for _, link := range data.Links {
		suffix := normalizeDNSSuffix(link.Suffix)
		if suffix == "" {
			continue
		}
		if !validDNSSuffix(suffix) {
			context.RequireManual = true
			context.Warnings = append(context.Warnings, "An adapter DNS suffix could not be represented; configure dns.rules manually")
			continue
		}
		servers, valid := normalizedSystemServers(link.Servers)
		scope := DNSSystemScope{Suffix: suffix, Servers: servers, Interface: link.Name}
		if !valid || len(servers) == 0 || link.Name == "" {
			scope.Unavailable = true
			scope.Reason = "adapter DNS scope has no usable server/interface"
		}
		context.Scopes = append(context.Scopes, scope)
		if !containsDNSValue(context.SearchDomains, suffix) && len(context.SearchDomains) < 32 {
			context.SearchDomains = append(context.SearchDomains, suffix)
		}
	}
	for _, policy := range data.NRPT {
		servers, valid := normalizedSystemServers(policy.Servers)
		device, bound := windowsDNSScopeInterface(data, servers)
		for _, namespace := range policy.Namespaces {
			suffix := normalizeDNSSuffix(strings.TrimPrefix(namespace, "."))
			if namespace == "." {
				suffix = "."
			}
			if !validDNSSuffix(suffix) {
				context.RequireManual = true
				context.Warnings = append(context.Warnings, "An NRPT namespace is not supported; configure dns.rules explicitly")
				continue
			}
			scope := DNSSystemScope{Suffix: suffix, Servers: servers, Interface: device, Exact: !strings.HasPrefix(namespace, ".")}
			if policy.Secure || policy.QueryPolicy != "" || !valid || !bound || len(servers) == 0 {
				scope.Unavailable = true
				scope.Reason = "NRPT secure/query policy or interface selection requires explicit DNS configuration"
			}
			context.Scopes = append(context.Scopes, scope)
		}
	}
	return context, nil
}

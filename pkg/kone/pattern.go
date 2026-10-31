//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/xjdrew/kone/pkg/geoip"
)

type Pattern interface {
	Proxy() string
	Match(val interface{}) bool
}

// DOMAIN
type DomainPattern struct {
	proxy  string
	domain string
}

func (p DomainPattern) Proxy() string {
	return p.proxy
}

func (p DomainPattern) Match(val interface{}) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}

	v = strings.ToLower(v)
	return v == p.domain
}

func NewDomainPattern(proxy, domain string) Pattern {
	return DomainPattern{
		proxy:  proxy,
		domain: strings.ToLower(domain),
	}
}

// DOMAIN-SUFFIX
type DomainSuffixPattern struct {
	proxy  string
	suffix string
}

func (p DomainSuffixPattern) Proxy() string {
	return p.proxy
}

func (p DomainSuffixPattern) Match(val interface{}) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}

	v = normalizeDomain(v)
	return v == p.suffix || strings.HasSuffix(v, "."+p.suffix)
}

func NewDomainSuffixPattern(proxy, suffix string) Pattern {
	return DomainSuffixPattern{
		proxy:  proxy,
		suffix: normalizeDomain(suffix),
	}
}

// DOMAIN-KEYWORD
type DomainKeywordPattern struct {
	proxy string
	key   string
}

func (p DomainKeywordPattern) Proxy() string {
	return p.proxy
}

func (p DomainKeywordPattern) Match(val interface{}) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}
	v = strings.ToLower(v)
	return strings.Contains(v, p.key)
}

func NewDomainKeywordPattern(proxy string, key string) Pattern {
	return DomainKeywordPattern{
		proxy: proxy,
		key:   strings.ToLower(key),
	}
}

// GEOIP
type GEOIPPattern struct {
	proxy    string
	country  string
	database *geoip.Database
}

func (p GEOIPPattern) Proxy() string {
	return p.proxy
}

func (p GEOIPPattern) Match(val interface{}) bool {
	var country string
	database := p.database
	if database == nil {
		database = geoip.Builtin()
	}
	switch ip := val.(type) {
	case netip.Addr:
		country = database.Country(ip)
	case net.IP:
		address, _ := netip.AddrFromSlice(ip)
		country = database.Country(address)
	}

	return p.country == country
}

func NewGEOIPPattern(proxy string, country string) Pattern {
	return NewGEOIPPatternWithDatabase(proxy, country, geoip.Builtin())
}

func NewGEOIPPatternWithDatabase(proxy string, country string, database *geoip.Database) Pattern {
	return GEOIPPattern{
		proxy:    proxy,
		country:  country,
		database: database,
	}
}

// IP-CIDR
type IPCIDRPattern struct {
	proxy  string
	prefix netip.Prefix
}

func (p IPCIDRPattern) Proxy() string {
	return p.proxy
}

func (p IPCIDRPattern) Match(val interface{}) bool {
	switch ip := val.(type) {
	case net.IP:
		address, _ := netip.AddrFromSlice(ip)
		return p.prefix.Contains(address.Unmap())
	case netip.Addr:
		return p.prefix.Contains(ip.Unmap())
	}

	return false
}

func NewIPCIDRPattern(proxy string, prefix netip.Prefix) Pattern {
	return IPCIDRPattern{
		proxy:  proxy,
		prefix: prefix.Masked(),
	}
}

// FINAL
type FinalPattern struct {
	proxy string
}

func (p FinalPattern) Proxy() string {
	return p.proxy
}

func (p FinalPattern) Match(val interface{}) bool {
	return true
}

func NewFinalPattern(proxy string) FinalPattern {
	return FinalPattern{proxy: proxy}
}

func CreatePattern(rc RuleConfig) Pattern {
	proxy := rc.Outbound
	pattern := rc.Pattern
	schema := strings.ToUpper(rc.Schema)

	switch schema {
	case "DOMAIN":
		return NewDomainPattern(proxy, pattern)
	case "DOMAIN-SUFFIX":
		return NewDomainSuffixPattern(proxy, pattern)
	case "DOMAIN-KEYWORD":
		return NewDomainKeywordPattern(proxy, pattern)
	case "IP-CIDR":
		prefix, err := netip.ParsePrefix(pattern)
		if err == nil && prefix.Addr().Is4() {
			return NewIPCIDRPattern(proxy, prefix)
		}
	case "IP-CIDR6":
		prefix, err := netip.ParsePrefix(pattern)
		if err == nil && prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			return NewIPCIDRPattern(proxy, prefix)
		}
	case "GEOIP":
		return NewGEOIPPattern(proxy, pattern)
	case "FINAL":
		return NewFinalPattern(proxy)
	}
	slog.Error("Invalid rule", "rule_type", rc.Schema, "pattern", rc.Pattern, "outbound", rc.Outbound)
	return nil
}

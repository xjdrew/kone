//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"net"
	"strings"

	"github.com/xjdrew/kone/geoip"
	"github.com/xjdrew/kone/tcpip"
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

	v = strings.ToLower(v)
	return strings.HasSuffix(v, p.suffix)
}

func NewDomainSuffixPattern(proxy, suffix string) Pattern {
	return DomainSuffixPattern{
		proxy:  proxy,
		suffix: strings.ToLower(suffix),
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
	proxy   string
	country string
}

func (p GEOIPPattern) Proxy() string {
	return p.proxy
}

func (p GEOIPPattern) Match(val interface{}) bool {
	var country string
	switch ip := val.(type) {
	case uint32:
		country = geoip.QueryCountry(ip)
	case net.IP:
		country = geoip.QueryCountryByIP(ip)
	}

	return p.country == country
}

func NewGEOIPPattern(proxy string, country string) Pattern {
	return GEOIPPattern{
		proxy:   proxy,
		country: country,
	}
}

// IP-CIDR
type IPCIDRPattern struct {
	proxy string
	ipNet *net.IPNet
}

func (p IPCIDRPattern) Proxy() string {
	return p.proxy
}

func (p IPCIDRPattern) Match(val interface{}) bool {
	switch ip := val.(type) {
	case net.IP:
		return p.ipNet.Contains(ip)
	case uint32:
		return p.ipNet.Contains(tcpip.ConvertUint32ToIPv4(ip))
	}

	return false
}

func NewIPCIDRPattern(proxy string, ipNet *net.IPNet) Pattern {
	return IPCIDRPattern{
		proxy: proxy,
		ipNet: ipNet,
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
	proxy := rc.Proxy
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
		fallthrough
	case "IP-CIDR6":
		if proxy == "DIRECT" { // all IPNet default proxy is DIRECT
			logger.Debugf("skip DIRECT rule: %s,%s,%s", rc.Schema, rc.Pattern, rc.Proxy)
			return nil
		}
		_, ipNet, err := net.ParseCIDR(pattern)
		if err == nil {
			return NewIPCIDRPattern(proxy, ipNet)
		}
	case "GEOIP":
		return NewGEOIPPattern(proxy, pattern)
	case "FINAL":
		return NewFinalPattern(proxy)
	}
	logger.Errorf("invalid rule: %s,%s,%s", rc.Schema, rc.Pattern, rc.Proxy)
	return nil
}

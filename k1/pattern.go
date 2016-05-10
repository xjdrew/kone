package k1

import (
	"net"
	"sort"
	"strings"

	"github.com/xjdrew/kone/geoip"
	"github.com/xjdrew/kone/tcpip"
)

const (
	schemeDomainSuffix  = "DOMAIN-SUFFIX"
	schemeDomainKeyword = "DOMAIN-KEYWORD"
	schemeIPCountry     = "IP-COUNTRY"
	schemeIPCIDR        = "IP-CIDR"
)

type Pattern interface {
	Proxy() string
	Match(val interface{}) bool
}

// DOMAIN-SUFFIX
type DomainSuffixPattern struct {
	proxy string
	vals  map[string]bool
}

func (p *DomainSuffixPattern) Proxy() string {
	return p.proxy
}

func (p *DomainSuffixPattern) Match(val interface{}) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}
	for {
		if p.vals[v] {
			return true
		}

		pos := strings.Index(v, ".")
		if pos < 0 {
			break
		}
		v = v[pos+1:]
	}
	return false
}

func NewDomainSuffixPattern(proxy string, vals []string) Pattern {
	p := new(DomainSuffixPattern)
	p.proxy = proxy
	p.vals = make(map[string]bool)
	for _, val := range vals {
		if len(val) > 0 { // ignore empty suffix
			p.vals[val] = true
		}
	}
	return p
}

// DOMAIN-KEYWORD
type DomainKeywordPattern struct {
	proxy string
	vals  map[string]bool
}

func (p *DomainKeywordPattern) Proxy() string {
	return p.proxy
}

func (p *DomainKeywordPattern) Match(val interface{}) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}
	for k := range p.vals {
		if strings.Index(v, k) >= 0 {
			return true
		}
	}
	return false
}

func NewDomainKeywordPattern(proxy string, vals []string) Pattern {
	p := new(DomainKeywordPattern)
	p.proxy = proxy
	p.vals = make(map[string]bool)
	for _, val := range vals {
		if len(val) > 0 { // ignore empty keyword
			p.vals[val] = true
		}
	}
	return p
}

// IP-COUNTRY
type IPCountryPattern struct {
	proxy string
	vals  map[string]bool
}

func (p *IPCountryPattern) Proxy() string {
	return p.proxy
}

func (p *IPCountryPattern) Match(val interface{}) bool {
	var country string
	switch ip := val.(type) {
	case uint32:
		country = geoip.QueryCountry(ip)
	case net.IP:
		country = geoip.QueryCountryByIP(ip)
	}

	return p.vals[country]
}

func NewIPCountryPattern(proxy string, vals []string) Pattern {
	p := new(IPCountryPattern)
	p.proxy = proxy
	p.vals = make(map[string]bool)
	for _, val := range vals {
		if len(val) > 0 { // ignore empty country
			p.vals[val] = true
		}
	}
	return p
}

// IPRangeArray
type IPRange struct {
	Start uint32
	End   uint32
}
type IPRangeArray []IPRange

func (a IPRangeArray) Len() int           { return len(a) }
func (a IPRangeArray) Less(i, j int) bool { return a[i].End < a[j].End }
func (a IPRangeArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func (a IPRangeArray) Contains(ip uint32) bool {
	l := len(a)
	i := sort.Search(l, func(i int) bool {
		n := a[i]
		return n.End >= ip
	})

	if i < l {
		n := a[i]
		if n.Start <= ip {
			return true
		}
	}
	return false
}

func (a IPRangeArray) ContainsIP(ip net.IP) bool {
	return a.Contains(tcpip.ConvertIPv4ToUint32(ip))
}

// IP-CIDR
type IPCIDRPattern struct {
	proxy string
	vals  IPRangeArray
}

func (p *IPCIDRPattern) Proxy() string {
	return p.proxy
}

func (p *IPCIDRPattern) Match(val interface{}) bool {
	switch ip := val.(type) {
	case uint32:
		return p.vals.Contains(ip)
	case net.IP:
		return p.vals.ContainsIP(ip)
	}

	return false
}

func NewIPCIDRPattern(proxy string, vals []string) Pattern {
	p := new(IPCIDRPattern)
	p.proxy = proxy
	for _, val := range vals {
		if _, ipNet, err := net.ParseCIDR(val); err == nil {
			start := tcpip.ConvertIPv4ToUint32(ipNet.IP)
			_end := start + ^tcpip.ConvertIPv4ToUint32(net.IP(ipNet.Mask))
			p.vals = append(p.vals, IPRange{
				Start: start,
				End:   _end,
			})
		}
	}

	sort.Sort(p.vals)
	return p
}

var patternSchemes map[string]func(string, []string) Pattern

func init() {
	patternSchemes = make(map[string]func(string, []string) Pattern)
	patternSchemes[schemeDomainSuffix] = NewDomainSuffixPattern
	patternSchemes[schemeDomainKeyword] = NewDomainKeywordPattern
	patternSchemes[schemeIPCountry] = NewIPCountryPattern
	patternSchemes[schemeIPCIDR] = NewIPCIDRPattern
}

func IsExistPatternScheme(scheme string) bool {
	_, ok := patternSchemes[scheme]
	return ok
}

func CreatePattern(config *PatternConfig) Pattern {
	if f := patternSchemes[config.Scheme]; f != nil {
		return f(config.Proxy, config.V)
	}
	return nil
}

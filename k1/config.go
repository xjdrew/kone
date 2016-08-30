//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"fmt"
	"net"
	"strings"

	"gopkg.in/gcfg.v1"
)

type GeneralConfig struct {
	Tun     string // tun name
	Network string // dns network
}

type NatConfig struct {
	ListenPort   uint16 `gcfg:"listen-port"`
	NatPortStart uint16 `gcfg:"nat-port-start"`
	NatPortEnd   uint16 `gcfg:"nat-port-end"`
}

type DnsConfig struct {
	DnsPort         uint16   `gcfg:"dns-port"`
	DnsTtl          uint     `gcfg:"dns-ttl"`
	DnsPacketSize   uint16   `gcfg:"dns-packet-size"`
	DnsReadTimeout  uint     `gcfg:"dns-read-timeout"`
	DnsWriteTimeout uint     `gcfg:"dns-write-timeout"`
	Nameserver      []string // backend dns
}

type RouteConfig struct {
	V []string
}

type ProxyConfig struct {
	Url     string
	Default bool
}

type PatternConfig struct {
	Proxy  string
	Scheme string
	V      []string
}

type RuleConfig struct {
	Pattern []string
	Final   string
}

type KoneConfig struct {
	General GeneralConfig
	TCP     NatConfig
	UDP     NatConfig
	Dns     DnsConfig
	Route   RouteConfig
	Proxy   map[string]*ProxyConfig
	Pattern map[string]*PatternConfig
	Rule    RuleConfig
}

func (cfg *KoneConfig) isValidProxy(proxy string) bool {
	if proxy == "" {
		return true
	}
	_, ok := cfg.Proxy[proxy]
	return ok
}

func (cfg *KoneConfig) checkGeneral() error {
	general := cfg.General

	ip, _, err := net.ParseCIDR(general.Network)
	if err != nil {
		return fmt.Errorf("[check general] invalid network: %s", general.Network)
	}

	if ip = ip.To4(); ip == nil || ip[3] == 0 {
		return fmt.Errorf("[check general] invalid ip: %s", ip)
	}

	return nil
}

func (cfg *KoneConfig) checkNat() error {
	check := func(nat NatConfig) error {
		// nat port range
		if nat.NatPortStart >= nat.NatPortEnd {
			return fmt.Errorf("invalid nat port range [%d, %d)", nat.NatPortStart, nat.NatPortEnd)
		}

		// listen-port should not in nat port range
		if nat.ListenPort >= nat.NatPortStart && nat.ListenPort < nat.NatPortEnd {
			return fmt.Errorf("nat port range should not contain listen port(%d)", nat.ListenPort)
		}
		return nil
	}

	if err := check(cfg.TCP); err != nil {
		fmt.Errorf("[check nat] tcp: %v", err)
	}

	if err := check(cfg.UDP); err != nil {
		fmt.Errorf("[check nat] udp: %v", err)
	}
	return nil
}

func (cfg *KoneConfig) checkRoute() error {
	for _, val := range cfg.Route.V {
		if _, _, err := net.ParseCIDR(val); err != nil {
			return fmt.Errorf("[check route] invalid value: %s", val)
		}
	}
	return nil
}

func (cfg *KoneConfig) checkRule() error {
	patterns := cfg.Pattern
	for name, patternConfig := range patterns {
		scheme := patternConfig.Scheme
		logger.Infof("[check pattern %q] scheme: %s", name, scheme)

		if !IsExistPatternScheme(scheme) {
			return fmt.Errorf("[check pattern %q] invalid scheme: %s", name, scheme)
		}

		proxy := patternConfig.Proxy
		if !cfg.isValidProxy(proxy) {
			return fmt.Errorf("[check pattern %q] invalid proxy: %s", name, proxy)
		}

		for _, val := range patternConfig.V {
			if scheme == schemeIPCIDR {
				if _, _, err := net.ParseCIDR(val); err != nil {
					return fmt.Errorf("[check pattern %q] invalid value: %s", name, val)
				}
			}
		}
	}

	rule := cfg.Rule
	for _, pattern := range rule.Pattern {
		logger.Infof("[check rule] pattern: %s", pattern)
		if _, ok := patterns[pattern]; !ok {
			return fmt.Errorf("[check rule] invalid pattern: %q", pattern)
		}
	}

	if !cfg.isValidProxy(rule.Final) {
		return fmt.Errorf("[check rule] invalid final proxy: %q", rule.Final)
	}
	logger.Infof("[check rule] final proxy: %q", rule.Final)

	return nil
}

func (cfg *KoneConfig) fixDns() error {
	dns := cfg.Dns

	if len(dns.Nameserver) == 0 {
		return fmt.Errorf("[check dns] no backend name server")
	}

	for index, nameserver := range dns.Nameserver {
		logger.Infof("[check dns] nameserver: %s", nameserver)
		server := nameserver
		if i := strings.IndexByte(nameserver, ':'); i < 0 {
			server = fmt.Sprintf("%s:%d", nameserver, dnsDefaultPort)
		}
		if _, err := net.ResolveUDPAddr("udp", server); err != nil {
			return fmt.Errorf("[check dns] invalid backend name server: %s", nameserver)
		}
		dns.Nameserver[index] = server
	}
	return nil
}

func (cfg *KoneConfig) check() (err error) {
	if err = cfg.checkGeneral(); err != nil {
		return
	}

	if err = cfg.checkNat(); err != nil {
		return
	}

	if err = cfg.checkRoute(); err != nil {
		return
	}

	if err = cfg.checkRule(); err != nil {
		return
	}

	if err = cfg.fixDns(); err != nil {
		return
	}
	return
}

func ParseConfig(filename string) (*KoneConfig, error) {
	cfg := new(KoneConfig)

	// set default value
	cfg.General.Network = "10.192.0.1/16"

	cfg.TCP.ListenPort = 82
	cfg.TCP.NatPortStart = 10000
	cfg.TCP.NatPortEnd = 60000

	cfg.UDP.ListenPort = 82
	cfg.UDP.NatPortStart = 10000
	cfg.UDP.NatPortEnd = 60000

	cfg.Dns.DnsPort = dnsDefaultPort
	cfg.Dns.DnsTtl = dnsDefaultTtl
	cfg.Dns.DnsPacketSize = dnsDefaultPacketSize
	cfg.Dns.DnsReadTimeout = dnsDefaultReadTimeout
	cfg.Dns.DnsWriteTimeout = dnsDefaultWriteTimeout

	// decode config value
	err := gcfg.ReadFileInto(cfg, filename)
	if err != nil {
		return nil, err
	}

	// set backend dns default value
	if len(cfg.Dns.Nameserver) == 0 {
		cfg.Dns.Nameserver = append(cfg.Dns.Nameserver, "114.114.114.114")
		cfg.Dns.Nameserver = append(cfg.Dns.Nameserver, "223.5.5.5")
	}

	err = cfg.check()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

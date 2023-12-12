//
//   date  : 2023-12-12
//   author: xjdrew
//

package util

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/gcfg.v1"
)

type GeneralConfig struct {
	ManagerAddr string   `ini:"manager-addr"`
	LogLevel    string   `ini:"log-level"`
	DnsServer   []string `ini:"dns-server" delim:","`
}

type CoreConfig struct {
	Network         string // tun network
	TcpListenPort   uint16 `ini:"tcp-listen-port"`
	TcpNatPortStart uint16 `ini:"tcp-nat-port-start"`
	TcpNatPortEnd   uint16 `ini:"tcp-nat-port-end"`
	UdpListenPort   uint16 `ini:"udp-listen-port"`
	UdpNatPortStart uint16 `ini:"udp-nat-port-start"`
	UdpNatPortEnd   uint16 `ini:"udp-nat-port-end"`
	DnsPort         uint16 `ini:"dns-port"`
	DnsTtl          uint   `ini:"dns-ttl"`
	DnsPacketSize   uint16 `ini:"dns-packet-size"`
	DnsReadTimeout  uint   `ini:"dns-read-timeout"`
	DnsWriteTimeout uint   `ini:"dns-write-timeout"`
}

type RouteConfig struct {
	V []string
}

type ProxyConfig struct {
	Url     string
	Default bool
}

type RuleConfig struct {
	Scheme  string
	Pattern string
	Proxy   string
}

type KoneConfig struct {
	General GeneralConfig
	Core    CoreConfig
	Proxy   map[string]string
	Rule    []RuleConfig
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
		return fmt.Errorf("[check nat] tcp: %v", err)
	}

	if err := check(cfg.UDP); err != nil {
		return fmt.Errorf("[check nat] udp: %v", err)
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
	cfg.Core.Network = "10.192.0.1/16"
	cfg.Core.TcpListenPort = 82
	cfg.Core.TcpNatPortStart = 10000
	cfg.Core.TcpNatPortEnd = 60000

	cfg.Core.UdpListenPort = 82
	cfg.Core.UdpNatPortStart = 10000
	cfg.Core.UdpNatPortEnd = 60000

	cfg.Core.DnsPort = dnsDefaultPort
	cfg.Core.DnsTtl = dnsDefaultTtl
	cfg.Core.DnsPacketSize = dnsDefaultPacketSize
	cfg.Core.DnsReadTimeout = dnsDefaultReadTimeout
	cfg.Core.DnsWriteTimeout = dnsDefaultWriteTimeout

	// decode config value
	err := gcfg.ReadFileInto(cfg, filename)
	if err != nil {
		return nil, err
	}

	// read from env and set to config
	if os.Getenv("DEFAULT_PROXY") != "" {
		cfg.Proxy["A"].Url = os.Getenv("DEFAULT_PROXY")
	}
	logger.Infof("Default A URL Proxy: %q", cfg.Proxy["A"].Url)

	// remove default final proxy A
	if os.Getenv("NO_DEFAULT_FINAL_PROXY") != "" {
		cfg.Rule.Final = ""
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

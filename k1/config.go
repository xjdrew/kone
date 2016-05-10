package k1

import (
	"fmt"
	"net"
	"strings"

	"gopkg.in/gcfg.v1"
)

type GeneralConfig struct {
	Tun           string // tun name
	IP            string // tun ip
	Network       string // dns network
	ForwarderPort uint16 `gcfg:"forwarder-port"`
	NatFromPort   uint16 `gcfg:"nat-from-port"`
	NatToPort     uint16 `gcfg:"nat-to-port"`
}

type DnsConfig struct {
	DnsPort    uint16   `gcfg:"dns-port"` // dns port
	Nameserver []string // backend dns
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
	Dns     DnsConfig
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

	// check ip format
	ip := net.ParseIP(general.IP).To4()
	if ip == nil {
		return fmt.Errorf("[check general] invalid ipv4 address: %s", general.IP)
	}

	_, subnet, err := net.ParseCIDR(general.Network)
	if err != nil {
		return fmt.Errorf("[check general] invalid network: %s", general.Network)
	}

	if subnet.Contains(ip) {
		return fmt.Errorf("[check general] subnet(%s) should not contain address(%s)", subnet, ip)
	}

	// nat port range
	if general.NatFromPort >= general.NatToPort {
		return fmt.Errorf("[check general] invalid nat port range [%d, %d)", general.NatFromPort, general.NatToPort)
	}

	// forwarder-port should not in nat port range
	if general.ForwarderPort >= general.NatFromPort && general.ForwarderPort < general.NatToPort {
		return fmt.Errorf("[check general] nat port range should not contain forwarder port(%d)", general.ForwarderPort)
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

func (cfg *KoneConfig) check() error {
	if err := cfg.checkGeneral(); err != nil {
		return err
	}

	if err := cfg.checkRule(); err != nil {
		return err
	}

	if err := cfg.fixDns(); err != nil {
		return err
	}
	return nil
}

func ParseConfig(filename string) (*KoneConfig, error) {
	cfg := new(KoneConfig)

	// set default value
	cfg.General.IP = "10.16.0.1"
	cfg.General.Network = "10.17.0.0/16"

	cfg.General.ForwarderPort = 82
	cfg.General.NatFromPort = 10000
	cfg.General.NatToPort = 60000

	cfg.Dns.DnsPort = dnsDefaultPort

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

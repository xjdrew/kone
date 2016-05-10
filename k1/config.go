package k1

import (
	"fmt"
	"net"

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

	// nat port range
	if general.NatFromPort >= general.NatToPort {
		return fmt.Errorf("invalid nat port range [%d, %d)", general.NatFromPort, general.NatToPort)
	}

	// forwarder-port should not in nat port range
	if general.ForwarderPort >= general.NatFromPort && general.ForwarderPort < general.NatToPort {
		return fmt.Errorf("nat port range should not contain forwarder port(%d)", general.ForwarderPort)
	}
	return nil
}

func (cfg *KoneConfig) checkRule() error {
	patterns := cfg.Pattern
	for name, patternConfig := range patterns {
		scheme := patternConfig.Scheme
		if !IsExistPatternScheme(scheme) {
			return fmt.Errorf("[pattern(%s)] invalid scheme: %s", name, scheme)
		}

		proxy := patternConfig.Proxy
		if !cfg.isValidProxy(proxy) {
			return fmt.Errorf("[pattern(%s)] invalid proxy: %s", name, proxy)
		}

		for _, val := range patternConfig.V {
			if scheme == schemeIPCIDR {
				if _, _, err := net.ParseCIDR(val); err != nil {
					return fmt.Errorf("[pattern(%s)] invalid value: %s", name, val)
				}
			}
		}
	}

	rule := cfg.Rule
	if !cfg.isValidProxy(rule.Final) {
		return fmt.Errorf("[rule] invalid final proxy: %s", rule.Final)
	}

	for _, pattern := range rule.Pattern {
		if _, ok := patterns[pattern]; !ok {
			return fmt.Errorf("[rule] invalid pattern: %s", pattern)
		}
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

	cfg.Dns.DnsPort = 53

	// decode config value
	err := gcfg.ReadFileInto(cfg, filename)
	if err != nil {
		return nil, err
	}

	err = cfg.check()
	if err != nil {
		return nil, err
	}

	if len(cfg.Dns.Nameserver) == 0 {
		cfg.Dns.Nameserver = append(cfg.Dns.Nameserver, "114.114.114.114")
	}
	return cfg, nil
}

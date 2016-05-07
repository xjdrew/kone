package k1

import (
	"fmt"

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
	Proxy string
	Type  string
	V     string
}

type RuleConfig struct {
	Pattern []string
	Final   string
}

type KoneConfig struct {
	General  GeneralConfig
	Dns      DnsConfig
	Proxies  map[string]*ProxyConfig
	Patterns map[string]*PatternConfig
	Rules    RuleConfig
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

func (cfg *KoneConfig) check() error {
	if err := cfg.checkGeneral(); err != nil {
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

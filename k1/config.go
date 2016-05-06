package k1

import (
	"fmt"

	"gopkg.in/gcfg.v1"
)

type GeneralConfig struct {
	Tun             string   // tun name
	IP              string   // tun ip
	DnsPort         uint16   `gcfg:"dns-port"` // dns port
	Dns             []string // backend dns
	Network         string   // dns network
	HijackNoMatched bool     `gcfg:"hijack-no-matched"`
	ForwarderPort   uint16   `gcfg:"forwarder-port"`
	NatFromPort     uint16   `gcfg:"nat-from-port"`
	NatToPort       uint16   `gcfg:"nat-to-port"`
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
}

type KoneConfig struct {
	General  GeneralConfig
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

	// forwarder-port and dns-port should not in nat port range
	if general.ForwarderPort >= general.NatFromPort && general.ForwarderPort < general.NatToPort {
		return fmt.Errorf("nat port range should not contain forwarder port(%d)", general.ForwarderPort)
	}
	if general.DnsPort >= general.NatFromPort && general.DnsPort < general.NatToPort {
		return fmt.Errorf("nat port range should not contain dns port(%d)", general.DnsPort)
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
	cfg.General.ForwarderPort = 82
	cfg.General.NatFromPort = 10000
	cfg.General.NatToPort = 60000

	// decode config value
	err := gcfg.ReadFileInto(cfg, filename)
	if err != nil {
		return nil, err
	}

	err = cfg.check()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

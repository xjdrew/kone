package k1

import (
	"github.com/BurntSushi/toml"
)

type GeneralConfig struct {
	IP     string
	Subnet string
	Dns    []string
}

type RuleConfig struct {
	Proxy string
	Type  string
	Value []string
}

type KoneConfig struct {
	General GeneralConfig
	Proxy   map[string]string
	Rules   []RuleConfig
}

func ParseConfig(filename string) (*KoneConfig, error) {
	cfg := new(KoneConfig)
	_, err := toml.DecodeFile(filename, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

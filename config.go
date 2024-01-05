//
//   date  : 2023-12-12
//   author: xjdrew
//

package kone

import (
	"os"
	"strings"
	"unicode"

	"github.com/xjdrew/dnsconfig"
	"gopkg.in/ini.v1"
)

func init() {
	ini.PrettyFormat = true
}

const (
	HTTP_PROXY  = "http_proxy"
	HTTPS_PROXY = "https_proxy"
	SOCKS_PROXY = "socks_proxy"
)

type GeneralConfig struct {
	ManagerAddr string `ini:"manager-addr"`
	LogLevel    string `ini:"log-level"`
}

type CoreConfig struct {
	Tun             string   `ini:"tun"`     // tun name
	Network         string   `ini:"network"` // tun network
	TcpListenPort   uint16   `ini:"tcp-listen-port"`
	TcpNatPortStart uint16   `ini:"tcp-nat-port-start"`
	TcpNatPortEnd   uint16   `ini:"tcp-nat-port-end"`
	UdpListenPort   uint16   `ini:"udp-listen-port"`
	UdpNatPortStart uint16   `ini:"udp-nat-port-start"`
	UdpNatPortEnd   uint16   `ini:"udp-nat-port-end"`
	DnsListenPort   uint16   `ini:"dns-listen-port"`
	DnsTtl          uint     `ini:"dns-ttl"`
	DnsPacketSize   uint16   `ini:"dns-packet-size"`
	DnsReadTimeout  uint     `ini:"dns-read-timeout"`
	DnsWriteTimeout uint     `ini:"dns-write-timeout"`
	DnsServer       []string `ini:"dns-server" delim:","`
}

type RuleConfig struct {
	Schema  string
	Pattern string
	Proxy   string
}

type KoneConfig struct {
	source interface{} // config source: file name or raw ini data
	inif   *ini.File   // parsed ini file

	General GeneralConfig
	Core    CoreConfig
	Proxy   map[string]string
	Rule    []RuleConfig
}

func (cfg *KoneConfig) parseRule(sec *ini.Section) (err error) {
	keys := sec.KeyStrings()

	var ops []string
	for _, key := range keys {
		ops = strings.FieldsFunc(key, func(c rune) bool {
			if c == ',' || unicode.IsSpace(c) {
				return true
			}
			return false
		})
		logger.Debugf("%s %v", key, ops)
		if len(ops) == 3 { // ignore invalid format
			cfg.Rule = append(cfg.Rule, RuleConfig{
				Schema:  ops[0],
				Pattern: ops[1],
				Proxy:   ops[2],
			})
		}
	}
	if len(ops) == 2 { //final rule
		cfg.Rule = append(cfg.Rule, RuleConfig{
			Schema: ops[0],
			Proxy:  ops[1],
		})
	}
	return nil
}

func (cfg *KoneConfig) check() (err error) {
	return nil
}

func (cfg *KoneConfig) GetSystemDnsservers() (servers []string) {
	config := dnsconfig.ReadDnsConfig()
	if config.Err != nil {
		logger.Warningf("read dns config failed: %v", config.Err)
		return []string{"114.114.114.114", "8.8.8.8"} // default
	}
	return config.Servers
}

func ParseConfig(source interface{}) (*KoneConfig, error) {
	cfg := new(KoneConfig)
	cfg.source = source

	// set default value
	cfg.Core.Network = "10.192.0.1/16"
	cfg.Core.TcpListenPort = 82
	cfg.Core.TcpNatPortStart = 10000
	cfg.Core.TcpNatPortEnd = 60000

	cfg.Core.UdpListenPort = 82
	cfg.Core.UdpNatPortStart = 10000
	cfg.Core.UdpNatPortEnd = 60000

	cfg.Core.DnsListenPort = DnsDefaultPort
	cfg.Core.DnsTtl = DnsDefaultTtl
	cfg.Core.DnsPacketSize = DnsDefaultPacketSize
	cfg.Core.DnsReadTimeout = DnsDefaultReadTimeout
	cfg.Core.DnsWriteTimeout = DnsDefaultWriteTimeout

	// decode config value
	f, err := ini.LoadSources(ini.LoadOptions{AllowBooleanKeys: true, KeyValueDelimiters: "="}, source)
	if err != nil {
		logger.Errorf("%v", err)
		return nil, err
	}
	cfg.inif = f

	err = f.MapTo(cfg)
	if err != nil {
		return nil, err
	}

	// init proxy
	if proxySection, err := f.GetSection("Proxy"); err == nil {
		cfg.Proxy = proxySection.KeysHash()
	}

	// read proxy from env
	if os.Getenv(HTTP_PROXY) != "" {
		cfg.Proxy[HTTP_PROXY] = os.Getenv(HTTP_PROXY)
		logger.Debugf("[env]set proxy %s=%s", HTTP_PROXY, cfg.Proxy[HTTP_PROXY])
	}

	if os.Getenv(HTTPS_PROXY) != "" {
		cfg.Proxy[HTTPS_PROXY] = os.Getenv(HTTPS_PROXY)
		logger.Debugf("[env]set proxy %s=%s", HTTPS_PROXY, cfg.Proxy[HTTPS_PROXY])
	}

	if os.Getenv(SOCKS_PROXY) != "" {
		cfg.Proxy[SOCKS_PROXY] = os.Getenv(SOCKS_PROXY)
		logger.Debugf("[env]set proxy %s=%s", SOCKS_PROXY, cfg.Proxy[SOCKS_PROXY])
	}

	// set backend dns default value
	if len(cfg.Core.DnsServer) == 0 {
		cfg.Core.DnsServer = cfg.GetSystemDnsservers()
	}

	// init rule
	if err := cfg.parseRule(f.Section("Rule")); err != nil {
		return nil, err
	}

	err = cfg.check()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

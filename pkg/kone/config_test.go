package kone

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const baseConfig = "[core]\ndns-server = ['1.1.1.1', '2001:4860:4860::8888']\n"

func cleanProxyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{HTTP_PROXY, HTTPS_PROXY, SOCKS_PROXY, "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
}

func parseTestConfig(t *testing.T, extra string) *KoneConfig {
	t.Helper()
	cfg, err := ParseConfig([]byte(baseConfig + extra))
	require.NoError(t, err)
	return cfg
}

func TestParseConfig(t *testing.T) {
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, `
[general]
log-format = 'json'
[proxies]
Proxy1 = 'http://proxy.example.com:8080'
Proxy2 = 'socks5://127.0.0.1:1080'
[[rules]]
type = 'DOMAIN-SUFFIX'
pattern = 'example.com'
proxy = 'Proxy1'
[[rules]]
type = 'FINAL'
proxy = 'DIRECT'
`)
	require.Equal(t, "127.0.0.1:9200", cfg.General.ManagerAddr)
	require.Equal(t, "json", cfg.General.LogFormat)
	require.Equal(t, uint16(82), cfg.Core.TcpListenPort)
	require.Equal(t, uint16(60000), cfg.Core.UdpNatPortEnd)
	require.Equal(t, []string{"1.1.1.1:53", "[2001:4860:4860::8888]:53"}, cfg.Core.DnsServer)
	require.Len(t, cfg.Rule, 2)
	require.Equal(t, "FINAL", cfg.Rule[1].Schema)
}

func TestProxyEnvironmentWithoutSection(t *testing.T) {
	cleanProxyEnv(t)
	t.Setenv(HTTP_PROXY, "http://127.0.0.1:8080")
	cfg := parseTestConfig(t, "")
	require.Equal(t, "http://127.0.0.1:8080", cfg.Proxy[HTTP_PROXY])
}

func TestUppercaseProxyEnvironment(t *testing.T) {
	cleanProxyEnv(t)
	t.Setenv("SOCKS_PROXY", "socks5://127.0.0.1:1080")
	cfg := parseTestConfig(t, "")
	require.Equal(t, "socks5://127.0.0.1:1080", cfg.Proxy[SOCKS_PROXY])
}

func TestConfigValidation(t *testing.T) {
	cleanProxyEnv(t)
	cases := []struct{ name, document, want string }{
		{"unknown key", baseConfig + "typo = 1", "unknown configuration key"},
		{"legacy INI", "[Core]\nnetwork = 10.192.0.1/16", "decode TOML"},
		{"invalid CIDR", baseConfig + "network = 'bad'", "core.network"},
		{"IPv6 network", baseConfig + "network = 'fd00::1/64'", "core.network"},
		{"tiny network", baseConfig + "network = '10.0.0.1/31'", "core.network"},
		{"network address", baseConfig + "network = '10.0.0.0/24'", "host address"},
		{"broadcast", baseConfig + "network = '10.0.0.255/24'", "host address"},
		{"loopback", baseConfig + "network = '127.0.0.1/24'", "host address"},
		{"zero port", baseConfig + "tcp-listen-port = 0", "tcp-listen-port"},
		{"overflow port", baseConfig + "tcp-listen-port = 65536", "decode TOML"},
		{"negative port", baseConfig + "tcp-listen-port = -1", "decode TOML"},
		{"reversed range", baseConfig + "tcp-nat-port-start = 60000\ntcp-nat-port-end = 10000", "tcp-nat-port-start"},
		{"zero range", baseConfig + "udp-nat-port-start = 0", "udp-nat-port-start"},
		{"range collision", baseConfig + "tcp-listen-port = 10000", "overlaps"},
		{"DNS port collision", baseConfig + "dns-listen-port = 82", "dns-listen-port"},
		{"TTL", baseConfig + "dns-ttl = 0", "dns-ttl"},
		{"packet size", baseConfig + "dns-packet-size = 100", "dns-packet-size"},
		{"timeout", baseConfig + "dns-read-timeout = 301", "timeouts"},
		{"manager", baseConfig + "[general]\nmanager-addr = 'localhost:0'", "manager-addr"},
		{"log level", baseConfig + "[general]\nlog-level = 'verbose'", "log-level"},
		{"log format", baseConfig + "[general]\nlog-format = 'xml'", "log-format"},
		{"bad DNS", "[core]\ndns-server=['not-an-ip']", "dns-server[1]"},
		{"DNS loop", "[core]\ndns-server=['10.192.0.1']", "virtual network"},
		{"DNS port", "[core]\ndns-server=['1.1.1.1:0']", "dns-server[1]"},
		{"reserved proxy", baseConfig + "[proxies]\nDIRECT='http://127.0.0.1:8080'", "reserved proxy"},
		{"bad proxy", baseConfig + "[proxies]\nA='ftp://127.0.0.1:8080'", "proxies.A"},
		{"proxy no port", baseConfig + "[proxies]\nA='http://127.0.0.1'", "proxies.A"},
		{"missing proxy", baseConfig + "[[rules]]\ntype='FINAL'\nproxy='Missing'", "undefined proxy"},
		{"bad type", baseConfig + "[[rules]]\ntype='typo'\nproxy='DIRECT'", "unknown rule type"},
		{"empty domain", baseConfig + "[[rules]]\ntype='DOMAIN'\nproxy='DIRECT'", "domain pattern"},
		{"bad CIDR rule", baseConfig + "[[rules]]\ntype='IP-CIDR'\npattern='bad'\nproxy='DIRECT'", "IPv4 prefix"},
		{"unsupported IPv6", baseConfig + "[[rules]]\ntype='IP-CIDR6'\npattern='::/0'\nproxy='DIRECT'", "IPv6 interception"},
		{"country", baseConfig + "[[rules]]\ntype='GEOIP'\npattern='USA'\nproxy='DIRECT'", "country code"},
		{"FINAL order", baseConfig + "[[rules]]\ntype='FINAL'\nproxy='DIRECT'\n[[rules]]\ntype='FINAL'\nproxy='REJECT'", "FINAL must be last"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { _, err := ParseConfig([]byte(tc.document)); require.ErrorContains(t, err, tc.want) })
	}
	var cfg *KoneConfig
	require.Error(t, cfg.Validate())
	_, err := FromConfig(cfg)
	require.Error(t, err)
}

func TestConfigSourceOwnership(t *testing.T) {
	cleanProxyEnv(t)
	data := []byte(baseConfig)
	cfg, err := ParseConfig(data)
	require.NoError(t, err)
	data[0] = '!'
	_, err = ParseConfig(cfg.source)
	require.NoError(t, err)
	filename := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(filename, []byte(baseConfig), 0600))
	cfg, err = ParseConfig(filename)
	require.NoError(t, err)
	require.Equal(t, filename, cfg.source)
}

func TestConfigSecretsAreRedacted(t *testing.T) {
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, "[proxies]\nSecret='https://alice:supersecret@example.com:443'\n")
	data, err := cfg.RedactedTOML()
	require.NoError(t, err)
	require.NotContains(t, string(data), "alice")
	require.NotContains(t, string(data), "supersecret")
	require.Contains(t, cfg.Proxy["Secret"], "supersecret")
	_, err = ParseConfig([]byte(baseConfig + "[proxies]\nSecret='https://alice:supersecret@example.com:bad'\n"))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "supersecret")
}

func TestStructuredLogging(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	var out bytes.Buffer
	require.NoError(t, ConfigureLogging(&out, GeneralConfig{LogLevel: "info", LogFormat: "json"}, false))
	slog.Debug("hidden")
	slog.Info("Connection completed", "proxy", "office", "upload_bytes", int64(42))
	var event map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &event))
	require.Equal(t, "office", event["proxy"])
	require.Equal(t, float64(42), event["upload_bytes"])
	require.Equal(t, "kone", event["service"])
	require.NotContains(t, out.String(), "hidden")
	out.Reset()
	require.NoError(t, ConfigureLogging(&out, GeneralConfig{LogLevel: "info", LogFormat: "text"}, true))
	slog.Debug("visible", "key", "value")
	require.True(t, strings.Contains(out.String(), "key=value"))
}

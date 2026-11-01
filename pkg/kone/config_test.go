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

const baseConfig = "[dns]\nservers = ['1.1.1.1', '2001:4860:4860::8888']\n[core]\n"

func outboundByName(cfg *KoneConfig, name string) *OutboundConfig {
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Name == name {
			return &cfg.Outbounds[i]
		}
	}
	panic("missing test outbound: " + name)
}

func setTestOutbound(cfg *KoneConfig, name string, url string) {
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Name == name {
			cfg.Outbounds[i] = OutboundConfig{Name: name, URL: url}
			return
		}
	}
	cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{Name: name, URL: url})
}

func cleanProxyEnv(t testing.TB) {
	t.Helper()
	for _, key := range []string{HTTP_PROXY, HTTPS_PROXY, SOCKS_PROXY, "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
}

func TestRemovedRelayConfigurationIsRejected(t *testing.T) {
	cleanProxyEnv(t)
	for _, key := range []string{"tcp-listen-port", "tcp-nat-port-start", "tcp-nat-port-end", "udp-listen-port", "udp-nat-port-start", "udp-nat-port-end"} {
		_, err := ParseConfig([]byte("[core]\n" + key + "=10000"))
		require.ErrorContains(t, err, "unknown configuration key")
		require.ErrorContains(t, err, key)
	}
	_, err := ParseConfig([]byte("[dns]\nlisten-port=82"))
	require.NoError(t, err, "DNS no longer conflicts with an unused legacy UDP relay")
}

func TestUDPFallbackConfiguration(t *testing.T) {
	cleanProxyEnv(t)
	for _, target := range []string{"", BuiltinDirect, BuiltinReject} {
		cfg, err := ParseConfig([]byte("[[outbounds]]\nname='office'\nurl='http://127.0.0.1:8080'\nudp-fallback='" + target + "'"))
		require.NoError(t, err)
		require.Equal(t, target, cfg.Outbounds[0].UDPFallback)
	}
	for _, target := range []string{"DIRECT", "missing", "office", "other"} {
		_, err := ParseConfig([]byte("[[outbounds]]\nname='office'\nurl='http://127.0.0.1:8080'\nudp-fallback='" + target + "'\n[[outbounds]]\nname='other'\nurl='socks5://127.0.0.1:1080'"))
		require.ErrorContains(t, err, "udp-fallback must be direct or reject")
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
[[outbounds]]
name='Proxy1'
url='http://proxy.example.com:8080'
[[outbounds]]
name='Proxy2'
url='socks5://127.0.0.1:1080'
[[rules]]
type = 'DOMAIN-SUFFIX'
pattern = 'example.com'
outbound = 'Proxy1'
[[rules]]
type = 'FINAL'
outbound = 'direct'
`)
	require.Equal(t, "json", cfg.General.LogFormat)
	require.Equal(t, []string{"1.1.1.1:53", "[2001:4860:4860::8888]:53"}, cfg.DNS.Servers)
	require.Len(t, cfg.Rule, 2)
	require.Equal(t, "FINAL", cfg.Rule[1].Schema)
	require.Len(t, cfg.Outbounds, 2)
	require.Equal(t, OutboundProxy, NewRule(cfg.Rule, cfg.Outbounds).OutboundType("Proxy1"))
	redacted, err := cfg.RedactedTOML()
	require.NoError(t, err)
	roundtrip, err := ParseConfig(redacted)
	require.NoError(t, err)
	require.Equal(t, cfg.Outbounds, roundtrip.Outbounds)
}

func TestProxyEnvironmentWithoutSection(t *testing.T) {
	cleanProxyEnv(t)
	t.Setenv(HTTP_PROXY, "http://127.0.0.1:8080")
	cfg := parseTestConfig(t, "")
	require.Equal(t, "http://127.0.0.1:8080", outboundByName(cfg, HTTP_PROXY).URL)
}

func TestUppercaseProxyEnvironment(t *testing.T) {
	cleanProxyEnv(t)
	t.Setenv("SOCKS_PROXY", "socks5://127.0.0.1:1080")
	cfg := parseTestConfig(t, "")
	require.Equal(t, "socks5://127.0.0.1:1080", outboundByName(cfg, SOCKS_PROXY).URL)
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
		{"zero DNS port", "[dns]\nlisten-port = 0", "dns.listen-port"},
		{"TTL", "[dns]\nttl = 0", "dns.ttl"},
		{"packet size", "[dns]\npacket-size = 100", "dns.packet-size"},
		{"timeout", "[dns]\nread-timeout = 301", "timeouts"},
		{"manager", baseConfig + "[general]\nmanager-addr = 'localhost:0'", "manager-addr"},
		{"log level", baseConfig + "[general]\nlog-level = 'verbose'", "log-level"},
		{"log format", baseConfig + "[general]\nlog-format = 'xml'", "log-format"},
		{"bad DNS", "[dns]\nservers=['not-an-ip']", "dns.servers[1]"},
		{"DNS loop", "[dns]\nservers=['10.192.0.1']", "virtual network"},
		{"DNS port", "[dns]\nservers=['1.1.1.1:0']", "dns.servers[1]"},
		{"duplicate outbound", baseConfig + "[[outbounds]]\nname='A'\nurl='http://127.0.0.1:8080'\n[[outbounds]]\nname='A'\nurl='http://127.0.0.1:8081'", "duplicate outbound name"},
		{"reserved direct", baseConfig + "[[outbounds]]\nname='direct'\nurl='http://127.0.0.1:8080'", "reserved for built-in outbound direct"},
		{"reserved reject case", baseConfig + "[[outbounds]]\nname='REJECT'\nurl='http://127.0.0.1:8080'", "reserved for built-in outbound reject"},
		{"bad proxy", baseConfig + "[[outbounds]]\nname='A'\nurl='ftp://127.0.0.1:8080'", "outbounds[1]"},
		{"proxy no port", baseConfig + "[[outbounds]]\nname='A'\nurl='http://127.0.0.1'", "invalid proxy URL"},
		{"empty outbound name", "[[outbounds]]\nname=''\nurl='http://127.0.0.1:8080'", "name must be nonempty"},
		{"whitespace outbound name", "[[outbounds]]\nname=' bad'\nurl='http://127.0.0.1:8080'", "name must be nonempty"},
		{"missing outbound URL", "[[outbounds]]\nname='office'", "invalid proxy URL"},
		{"removed proxy type", "[[outbounds]]\nname='office'\ntype='proxy'\nurl='http://127.0.0.1:8080'", "unknown configuration key"},
		{"configured direct", "[[outbounds]]\nname='local'\ntype='direct'", "unknown configuration key"},
		{"configured reject", "[[outbounds]]\nname='blocked'\ntype='reject'", "unknown configuration key"},
		{"legacy proxies", "[proxies]\nSecret='https://alice:secret@example.com:443'", "unknown configuration key"},
		{"legacy DNS", "[core]\ndns-server=['1.1.1.1']", "unknown configuration key"},
		{"legacy rule", baseConfig + "[[rules]]\ntype='FINAL'\nproxy='direct'", "unknown configuration key"},
		{"missing outbound", baseConfig + "[[rules]]\ntype='FINAL'\noutbound='Missing'", "undefined outbound"},
		{"uppercase builtin reference", baseConfig + "[[rules]]\ntype='FINAL'\noutbound='DIRECT'", "undefined outbound"},
		{"bad type", baseConfig + "[[rules]]\ntype='typo'\noutbound='direct'", "unknown rule type"},
		{"empty domain", baseConfig + "[[rules]]\ntype='DOMAIN'\noutbound='direct'", "domain pattern"},
		{"bad CIDR rule", baseConfig + "[[rules]]\ntype='IP-CIDR'\npattern='bad'\noutbound='direct'", "IPv4 prefix"},
		{"unsupported IPv6", baseConfig + "[[rules]]\ntype='IP-CIDR6'\npattern='::/0'\noutbound='direct'", "IPv6 interception"},
		{"country", baseConfig + "[[rules]]\ntype='GEOIP'\npattern='USA'\noutbound='direct'", "country code"},
		{"FINAL order", baseConfig + "[[rules]]\ntype='FINAL'\noutbound='direct'\n[[rules]]\ntype='FINAL'\noutbound='reject'", "FINAL must be last"},
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
	cfg := parseTestConfig(t, "[[outbounds]]\nname='Secret'\nurl='https://alice:supersecret@example.com:443'\n")
	data, err := cfg.RedactedTOML()
	require.NoError(t, err)
	require.NotContains(t, string(data), "alice")
	require.NotContains(t, string(data), "supersecret")
	require.Contains(t, outboundByName(cfg, "Secret").URL, "supersecret")
	_, err = ParseConfig([]byte(baseConfig + "[[outbounds]]\nname='Secret'\nurl='https://alice:supersecret@example.com:bad'\n"))
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

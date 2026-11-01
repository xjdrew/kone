package kone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeoIPConfigurationValidatesExplicitLocalSource(t *testing.T) {
	cleanProxyEnv(t)
	for _, cfg := range []GeoIPConfig{
		{Provider: "unknown"}, {Provider: "builtin", File: "country.mmdb"},
		{Provider: "builtin", SHA256: strings.Repeat("a", 64)},
		{Provider: "ipinfo-lite"}, {Provider: "kone-json", File: "country.json", SHA256: "bad"},
		{Provider: "ipinfo-lite", File: "https://example.com/country.mmdb", SHA256: strings.Repeat("a", 64)},
		{Provider: "ipinfo-lite", File: `\\server\country.mmdb`, SHA256: strings.Repeat("a", 64)},
		{Provider: "ipinfo-lite", File: "country\n.mmdb", SHA256: strings.Repeat("a", 64)},
		{Provider: "ipinfo-lite", File: "country.mmdb", SHA256: strings.Repeat("A", 64)},
		{Provider: "ipinfo-lite", File: "country.mmdb", SHA256: strings.Repeat("g", 64)},
	} {
		require.Error(t, cfg.Validate(), "%+v", cfg)
		config := DefaultConfig()
		config.GeoIP = cfg
		require.Error(t, config.Validate())
	}
	for _, cfg := range []GeoIPConfig{{}, {Provider: "builtin"}, {Provider: "dbip-lite", File: "country.mmdb", SHA256: strings.Repeat("a", 64)}} {
		require.NoError(t, cfg.Validate())
	}
	data, digest := geoIPFixture(t, "CN", "configured-json")
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "country.json"), data, 0600))
	configuration := "[dns]\nservers=['127.0.0.1:5353']\n[geoip]\nprovider='kone-json'\nfile='country.json'\nsha256='" + digest + "'\n[[rules]]\ntype='GEOIP'\npattern='CN'\noutbound='reject'\n[[rules]]\ntype='FINAL'\noutbound='direct'\n"
	filename := filepath.Join(directory, "kone.toml")
	require.NoError(t, os.WriteFile(filename, []byte(configuration), 0600))
	config, err := ParseConfig(filename)
	require.NoError(t, err)
	require.NoError(t, config.ValidateGeoIPFile())
	engine, err := FromConfig(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, engine.Close()) })
	decision, err := engine.ExplainDecision("192.0.2.1:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, BuiltinReject, decision.Outbound)
	require.Equal(t, digest, decision.GeoIPSHA256)
	next := engine.Snapshot().Config
	next.GeoIP = GeoIPConfig{Provider: "builtin"}
	require.ErrorContains(t, engine.Reload(next), "restart")
	_, err = ParseManagedConfig([]byte(configuration))
	require.ErrorContains(t, err, "managed mode")
	_, err = ParseConfig([]byte("[geoip]\nprovider='builtin'\nunknown=true\n"))
	require.ErrorContains(t, err, "unknown configuration key")
	_, err = next.GeoIP.load("")
	require.NoError(t, err)
	_, err = (GeoIPConfig{Provider: "kone-json", File: filename, SHA256: digest}).load("")
	require.Error(t, err)
	_, err = (GeoIPConfig{Provider: "kone-json", File: directory, SHA256: digest}).load("")
	require.Error(t, err)
	_, err = (GeoIPConfig{Provider: "kone-json", File: "missing.json", SHA256: digest}).load(filename)
	require.Error(t, err)
	_, err = (GeoIPConfig{Provider: "builtin", File: "invalid"}).load("")
	require.Error(t, err)
	config.GeoIP.File = "missing.json"
	require.Error(t, config.ValidateGeoIPFile())
	_, err = FromConfig(config)
	require.ErrorContains(t, err, "GeoIP")
	var nilConfig *KoneConfig
	require.Error(t, nilConfig.ValidateGeoIPFile())
}

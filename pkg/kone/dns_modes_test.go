package kone

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSModesKeepDiscoveryAndHostOwnershipIndependent(t *testing.T) {
	for _, mode := range []string{"host", "gate"} {
		cfg := DefaultConfig()
		cfg.DNS.Mode = mode
		cfg.DNS.System = mode == "gate" // mode wins over the legacy boolean.
		cfg.DNS.ListenAddress = "192.0.2.10"
		require.Equal(t, mode == "host", cfg.DNS.SystemEnabled())
		require.NoError(t, cfg.Validate())
		discovered, err := effectiveDNSConfig(cfg.DNS, func() ([]string, error) { return []string{"192.0.2.53"}, nil })
		require.NoError(t, err)
		require.Equal(t, []string{"192.0.2.53:53"}, discovered.Servers)
		require.False(t, discovered.SystemContext.PublicFallback)
		for _, fault := range []error{nil, errors.New("no resolver")} {
			fallback, err := effectiveDNSConfig(cfg.DNS, func() ([]string, error) { return nil, fault })
			require.NoError(t, err)
			require.Equal(t, PublicDNSDefaults(), fallback.Servers)
			require.True(t, fallback.SystemContext.PublicFallback)
		}
		cfg.DNS.Servers = []string{"192.0.2.53:5353"}
		explicit, err := effectiveDNSConfig(cfg.DNS, func() ([]string, error) {
			t.Fatal("explicit servers must not be replaced by discovery")
			return nil, nil
		})
		require.NoError(t, err)
		require.Equal(t, cfg.DNS.Servers, explicit.Servers)
	}
	cfg := DefaultConfig()
	cfg.DNS.Mode = "invalid"
	require.Error(t, cfg.Validate())
	cfg.DNS.Mode = "gate"
	require.Error(t, cfg.Validate())
	cfg.DNS.ListenAddress = "224.0.0.1"
	require.Error(t, cfg.Validate())
}
func TestGateBindsSelectedLANAddressAndDoesNotGuideSystemDNS(t *testing.T) {
	for address, network := range map[string]string{"192.0.2.10": "udp4", "2001:db8::10": "udp6"} {
		cfg := DefaultConfig()
		cfg.DNS.Mode = "gate"
		cfg.DNS.System = true
		cfg.DNS.ListenAddress = address
		cfg.DNS.Servers = []string{"192.0.2.53"}
		one, err := FromConfig(cfg)
		require.NoError(t, err)
		defer one.Close()
		require.Equal(t, network, one.dns.server.Net)
		require.Contains(t, one.dns.server.Addr, address)
		require.Nil(t, one.dns.ipv6)
		require.NoError(t, CheckSystemDNS(t.Context(), cfg.DNS))
		cleanup, err := (systemNetwork{}).ConfigureSystemDNS(t.Context(), nil, cfg.Core, cfg.DNS)
		require.NoError(t, err)
		require.Nil(t, cleanup)
		status := one.DNSStatus()
		require.Equal(t, "gate", status.Mode)
		require.False(t, status.SystemRequested)
		cfg.DNS.Servers = []string{address}
		_, err = FromConfig(cfg)
		require.ErrorContains(t, err, "own Gate listener")
		cfg.DNS.Servers = []string{"192.0.2.53"}
		cfg.DNS.Rules = []DNSRouteConfig{{Suffix: "example", Servers: []string{address}}}
		_, err = FromConfig(cfg)
		require.ErrorContains(t, err, "split DNS")
	}
}

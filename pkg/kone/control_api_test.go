package kone

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreflightOnlyInspectsAndReportsBlockingConditions(t *testing.T) {
	cfg := DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, Preflight(ctx, cfg).Ready)
	require.False(t, Preflight(context.Background(), nil).Ready)
	cfg.Core.OutboundInterface = "missing-kone-preflight"
	report := Preflight(context.Background(), cfg)
	require.False(t, report.Ready)
	var codes []string
	for _, issue := range report.Issues {
		codes = append(codes, issue.Code)
	}
	require.Contains(t, codes, "outbound_interface")
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, device := range interfaces {
		cfg = DefaultConfig()
		cfg.Core.Tun = device.Name
		if cfg.Validate() != nil {
			continue
		}
		report = Preflight(context.Background(), cfg)
		codes = nil
		for _, issue := range report.Issues {
			codes = append(codes, issue.Code)
		}
		require.Contains(t, codes, "device_exists")
		break
	}
	addresses, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, value := range addresses {
		prefix, e := netip.ParsePrefix(value.String())
		if e != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() {
			continue
		}
		cfg = DefaultConfig()
		cfg.Core.Network = netip.PrefixFrom(prefix.Addr(), 24).String()
		if cfg.Validate() != nil {
			continue
		}
		report = Preflight(context.Background(), cfg)
		codes = nil
		for _, issue := range report.Issues {
			codes = append(codes, issue.Code)
		}
		require.Contains(t, codes, "network_overlap")
		break
	}
	require.Contains(t, SupportedStacks(), "system")
}

func TestManagedConfigurationRevisionSurvivesGeoIPAndReload(t *testing.T) {
	one := geoIPEngine(t)
	defer one.Close()
	require.Error(t, one.SetConfigVersion(0))
	require.NoError(t, one.SetConfigVersion(40))
	decision, err := one.ExplainDecision("example.com:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(40), decision.ConfigVersion)
	data, digest := geoIPFixture(t, "CN", "managed-data")
	require.NoError(t, one.ApplyGeoIP(data, digest, one.Snapshot().Version))
	decision, err = one.ExplainDecision("example.com:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(40), decision.ConfigVersion)
	require.NoError(t, one.ReloadVersion(one.Snapshot().Config, 45))
	decision, err = one.ExplainDecision("example.com:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, uint64(45), decision.ConfigVersion)
	require.NoError(t, one.Close())
	require.Error(t, one.SetConfigVersion(46))
}

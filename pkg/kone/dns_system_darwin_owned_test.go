package kone

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const ownedResolverID = "00112233-4455-6677-8899-aabbccddeeff"
const ownedResolverKey = "State:/Network/Service/" + ownedResolverID + "/DNS"

func ownedResolverProfile() string {
	return "<dictionary> {\n" +
		"__KONEOwner : " + ownedResolverID + "\n" +
		"__KONEInterface : utun42\n" +
		"ServerAddresses : <array> {\n0 : 127.0.0.1\n}\n" +
		"ServerPort : 1053\nSupplementalMatchOrders : <array> {\n0 : 1\n}\n" +
		"SupplementalMatchDomains : <array> {\n0 : \n}\n}\n"
}

const darwinOwnedResolver = "resolver #1\n nameserver[0] : 127.0.0.1\n port : 1053\n order : 1\n"
const darwinPhysicalResolver = "resolver #2\n nameserver[0] : 192.0.2.53\n search domain[0] : home.test\n order : 200000\n"
const darwinVPNResolver = "resolver #3\n domain : corp.test\n nameserver[0] : 10.0.0.53\n if_index : 5 (utun9)\n flags : Supplemental, Scoped\n"

func TestDarwinDNSDiscoveryExcludesOnlyVerifiedOwnedResolverAcrossProcesses(t *testing.T) {
	reads := []string{}
	read := func(ctx context.Context, script string) ([]byte, error) {
		require.NoError(t, ctx.Err())
		reads = append(reads, script)
		switch script {
		case darwinDNSStoreList:
			return []byte("subKey [0] = " + ownedResolverKey + "\n"), nil
		case "show " + ownedResolverKey + "\nquit\n":
			return []byte(ownedResolverProfile()), nil
		default:
			t.Fatalf("unexpected read-only script %q", script)
			return nil, nil
		}
	}
	observed, err := discoverDarwinDNSContext(t.Context(), []byte(darwinOwnedResolver+darwinPhysicalResolver+darwinVPNResolver), read)
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.53:53"}, observed.DefaultServers)
	require.Equal(t, []string{"home.test"}, observed.SearchDomains)
	require.Len(t, observed.Scopes, 1)
	require.Equal(t, "corp.test", observed.Scopes[0].Suffix)
	require.Equal(t, "utun9", observed.Scopes[0].Interface)
	require.Equal(t, []string{"10.0.0.53:53"}, observed.Scopes[0].Servers)
	require.Len(t, reads, 2)
	for _, system := range []bool{false, true} {
		cfg := defaultConfig().DNS
		cfg.System = system
		cfg.Servers = []string{"127.0.0.1:1053"}
		merged := mergeSystemDNSContext(cfg, observed, nil)
		require.Equal(t, []string{"192.0.2.53:53"}, merged.Servers, "both a second CLI and a privileged helper must avoid recursive capture")
		require.Len(t, merged.Rules, 1)
		require.Equal(t, []string{"10.0.0.53:53"}, merged.Rules[0].Servers)
		require.False(t, merged.SystemContext.RequireManual)
	}
	// The backend's selection confirmation intentionally still observes its own
	// resolver; filtering applies only to upstream discovery.
	unfiltered, err := parseDarwinDNSContext([]byte(darwinOwnedResolver + darwinPhysicalResolver))
	require.NoError(t, err)
	require.Equal(t, []string{"127.0.0.1:1053"}, unfiltered.DefaultServers)
}

func TestDarwinDNSDiscoveryNeverGuessesLoopbackOwnership(t *testing.T) {
	physical, err := discoverDarwinDNSContext(t.Context(), []byte(darwinPhysicalResolver), func(context.Context, string) ([]byte, error) {
		t.Fatal("a physical default does not need dynamic-store discovery")
		return nil, nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.53:53"}, physical.DefaultServers)
	for _, profile := range []string{"<dictionary> {\nServerAddresses : <array> {\n0 : 127.0.0.1\n}\n}\n"} {
		read := func(_ context.Context, script string) ([]byte, error) {
			if script == darwinDNSStoreList {
				return []byte("subKey [0] = " + ownedResolverKey), nil
			}
			return []byte(profile), nil
		}
		observed, err := discoverDarwinDNSContext(t.Context(), []byte(darwinOwnedResolver+darwinPhysicalResolver), read)
		require.NoError(t, err)
		require.Equal(t, []string{"127.0.0.1:1053"}, observed.DefaultServers)
		require.False(t, observed.ownedDefaultExcluded)
	}
}

func TestDarwinDNSDiscoveryExcludesVerifiedRootSupplementalResolver(t *testing.T) {
	read := func(_ context.Context, script string) ([]byte, error) {
		if script == darwinDNSStoreList {
			return []byte("subKey [0] = " + ownedResolverKey), nil
		}
		return []byte(ownedResolverProfile()), nil
	}
	root := strings.Replace(darwinOwnedResolver, "resolver #1\n", "resolver #1\n domain : .\n", 1)
	observed, err := discoverDarwinDNSContext(t.Context(), []byte(root+darwinPhysicalResolver+darwinVPNResolver), read)
	require.NoError(t, err)
	require.True(t, observed.ownedDefaultExcluded)
	require.Equal(t, []string{"192.0.2.53:53"}, observed.DefaultServers)
	require.Len(t, observed.Scopes, 1)
	require.Equal(t, "corp.test", observed.Scopes[0].Suffix)
	require.Equal(t, []string{"10.0.0.53:53"}, observed.Scopes[0].Servers)
}

func TestDarwinDNSDiscoveryFailsClosedOnUnverifiableOwnedSettings(t *testing.T) {
	for name, profile := range map[string]string{
		"owner":     strings.Replace(ownedResolverProfile(), ownedResolverID, "ffffffff-4455-6677-8899-aabbccddeeff", 1),
		"interface": strings.Replace(ownedResolverProfile(), "utun42", "en0", 1),
		"address":   strings.Replace(ownedResolverProfile(), "127.0.0.1", "192.0.2.1", 1),
		"port":      strings.Replace(ownedResolverProfile(), "1053", "65536", 1),
		"zero port": strings.Replace(ownedResolverProfile(), "1053", "0", 1),
		"order":     strings.Replace(ownedResolverProfile(), "0 : 1\n", "0 : 2\n", 1),
		"domain":    strings.Replace(ownedResolverProfile(), "0 : \n", "0 : corp.test\n", 1),
		"extra":     strings.Replace(ownedResolverProfile(), "ServerPort : 1053", "Extra : yes\nServerPort : 1053", 1),
		"corrupt":   "__KONEOwner : broken",
		"vanished":  "No such key",
	} {
		t.Run(name, func(t *testing.T) {
			read := func(_ context.Context, script string) ([]byte, error) {
				if script == darwinDNSStoreList {
					return []byte("subKey [0] = " + ownedResolverKey), nil
				}
				return []byte(profile), nil
			}
			observed, err := discoverDarwinDNSContext(t.Context(), []byte(darwinOwnedResolver+darwinPhysicalResolver), read)
			require.Error(t, err)
			require.True(t, observed.RequireManual)
			require.NotEmpty(t, observed.Warnings)
			require.Equal(t, []string{"127.0.0.1:1053"}, observed.DefaultServers, "never select public defaults after an ambiguous ownership check")
		})
	}
	for _, read := range []func(context.Context, string) ([]byte, error){
		nil,
		func(context.Context, string) ([]byte, error) { return nil, errors.New("store unavailable") },
		func(_ context.Context, script string) ([]byte, error) {
			if script == darwinDNSStoreList {
				return []byte("subKey [0] = " + ownedResolverKey), nil
			}
			return nil, errors.New("show unavailable")
		},
		func(context.Context, string) ([]byte, error) { return []byte("unexpected list"), nil },
	} {
		observed, err := discoverDarwinDNSContext(t.Context(), []byte(darwinOwnedResolver+darwinPhysicalResolver), read)
		require.Error(t, err)
		require.True(t, observed.RequireManual)
	}
}

func TestDarwinDNSOwnedCaptureWithoutOriginalDefaultRequiresManualConfiguration(t *testing.T) {
	read := func(_ context.Context, script string) ([]byte, error) {
		if script == darwinDNSStoreList {
			return []byte("subKey [0] = " + ownedResolverKey), nil
		}
		return []byte(ownedResolverProfile()), nil
	}
	observed, err := discoverDarwinDNSContext(t.Context(), []byte(darwinOwnedResolver+darwinVPNResolver), read)
	require.NoError(t, err)
	require.True(t, observed.RequireManual)
	require.Empty(t, observed.DefaultServers)
	cfg := defaultConfig().DNS
	cfg.Servers = []string{"127.0.0.1:1053"}
	merged := mergeSystemDNSContext(cfg, observed, nil)
	require.Empty(t, merged.Servers)
	require.True(t, merged.SystemContext.RequireManual)
	_, err = NewDns(testEngine(t), merged)
	require.ErrorContains(t, err, "requires explicit")
}

func TestDarwinDNSStoreKeysAreBoundedAndSafeForReadCommands(t *testing.T) {
	key2 := strings.ToUpper(ownedResolverID)
	keys, err := parseDarwinDNSStoreKeys([]byte("\nsubKey [0] = " + ownedResolverKey + "\nsubKey [1] = State:/Network/Service/" + key2 + "/DNS\nsubKey [2] = State:/Network/Service/VPN_Work-1.test/DNS\n"))
	require.NoError(t, err)
	require.Len(t, keys, 3)
	for _, input := range []string{
		"No such key", "no keys.", "", "\n",
	} {
		keys, err := parseDarwinDNSStoreKeys([]byte(input))
		require.NoError(t, err)
		require.Empty(t, keys)
	}
	tooMany := strings.Builder{}
	for i := range 65 {
		fmt.Fprintf(&tooMany, "subKey [%d] = State:/Network/Service/%08x-4455-6677-8899-aabbccddeeff/DNS\n", i, i)
	}
	for _, input := range []string{
		"show " + ownedResolverKey,
		"subKey [0] = Setup:/Network/Service/" + ownedResolverID + "/DNS",
		"subKey [0] = State:/Network/Service//DNS",
		"subKey [0] = State:/Network/Service/" + strings.Repeat("x", 129) + "/DNS",
		"subKey [0] = State:/Network/Service/unsafe name/DNS",
		"subKey [0] = State:/Network/Service/" + ownedResolverID + "; remove x/DNS",
		"subKey [0] = " + ownedResolverKey + "\nsubKey [1] = " + ownedResolverKey,
		strings.Repeat("x", 1<<20+1),
		strings.Repeat("x", 4097),
		tooMany.String(),
	} {
		_, err := parseDarwinDNSStoreKeys([]byte(input))
		require.Error(t, err)
	}
	_, _, expected, err := scopedDNSScript(ownedResolverID, "utun42", netip.MustParseAddr("127.0.0.1"), 1053)
	require.NoError(t, err)
	address, err := darwinOwnedResolverAddress(ownedResolverKey, expected)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:1053", address)
	expected["ServerPort"] = []string{"1053", "1054"}
	_, err = darwinOwnedResolverAddress(ownedResolverKey, expected)
	require.Error(t, err)
}

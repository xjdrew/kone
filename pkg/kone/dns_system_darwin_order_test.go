package kone

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinRootResolverUsesSearchOrderIndependentOfDisplayOrder(t *testing.T) {
	fixture := "resolver #4\n nameserver[0] : 127.0.0.1\n port : 10053\n order : 100\n"
	specific := "resolver #5\n domain : corp.test\n nameserver[0] : 10.0.0.53\n order : 0\n"
	scopedRoot := "resolver #6\n domain : .\n nameserver[0] : 10.0.1.53\n order : 0\n flags : Scoped\n if_index : 7 (utun2)\n"
	for _, rootDomain := range []string{"", " domain : .\n"} {
		owned := strings.Replace(darwinOwnedResolver, "resolver #1\n", "resolver #1\n"+rootDomain, 1)
		parts := []string{darwinPhysicalResolver, fixture, owned}
		for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
			t.Run(fmt.Sprintf("root=%q/order=%v", rootDomain, order), func(t *testing.T) {
				data := []byte(parts[order[0]] + parts[order[1]] + parts[order[2]] + specific + scopedRoot)
				selected, err := parseDarwinDNSContext(data)
				require.NoError(t, err)
				require.False(t, selected.RequireManual)
				require.Equal(t, []string{"127.0.0.1:1053"}, selected.DefaultServers)
				require.Len(t, selected.Scopes, 2)
				require.Equal(t, "corp.test", selected.Scopes[0].Suffix)
				require.Equal(t, []string{"10.0.0.53:53"}, selected.Scopes[0].Servers)
				require.Equal(t, ".", selected.Scopes[1].Suffix)
				require.Equal(t, "utun2", selected.Scopes[1].Interface)
				original, err := parseDarwinDNSContextExcluding(data, map[string]bool{"127.0.0.1:1053": true})
				require.NoError(t, err)
				require.Equal(t, []string{"127.0.0.1:10053"}, original.DefaultServers)
				physical, err := parseDarwinDNSContextExcluding(data, map[string]bool{"127.0.0.1:1053": true, "127.0.0.1:10053": true})
				require.NoError(t, err)
				require.Equal(t, []string{"192.0.2.53:53"}, physical.DefaultServers)
			})
		}
	}
}

func TestDarwinDefaultResolverUnknownOrderAndAmbiguityFailClosed(t *testing.T) {
	for name, roots := range map[string]string{
		"equal priority": darwinOwnedResolver + strings.Replace(darwinOwnedResolver, "1053", "1054", 1),
		"invalid order":  strings.Replace(darwinOwnedResolver, "order : 1", "order : unknown", 1),
		"negative order": strings.Replace(darwinOwnedResolver, "order : 1", "order : -1", 1),
		"overflow order": strings.Replace(darwinOwnedResolver, "order : 1", "order : 4294967296", 1),
		"options":        darwinOwnedResolver + "options : tls\n",
		"invalid port":   strings.Replace(darwinOwnedResolver, "port : 1053", "port : 0", 1),
		"no server":      "resolver #1\n order : 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			observed, err := parseDarwinDNSContext([]byte(darwinPhysicalResolver + roots))
			require.NoError(t, err)
			require.True(t, observed.RequireManual)
			require.Empty(t, observed.DefaultServers, "never silently select a less-preferred physical resolver")
			require.NotEmpty(t, observed.Warnings)
		})
	}
	for _, roots := range []string{
		darwinOwnedResolver + darwinOwnedResolver,
		strings.ReplaceAll(darwinPhysicalResolver, " order : 200000\n", "") + darwinOwnedResolver,
		strings.Replace(darwinOwnedResolver, "order : 1", "order : 0", 1),
		strings.Replace(darwinPhysicalResolver+darwinPhysicalResolver, "order : 200000", "order : 100", 1) + darwinOwnedResolver,
	} {
		observed, err := parseDarwinDNSContext([]byte(roots))
		require.NoError(t, err)
		require.False(t, observed.RequireManual)
		require.Equal(t, []string{"127.0.0.1:1053"}, observed.DefaultServers)
	}
}

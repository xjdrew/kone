package kone

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinIPv6KernelRouteWireAndOwnership(t *testing.T) {
	for _, cidr := range []string{"fd7a:203::/120", "fd7a:203::8/128", "::/1", "8000::/1"} {
		t.Run(cidr, func(t *testing.T) {
			r, _, operations := testDarwinRouteTable()
			_, subnet, _ := net.ParseCIDR(cidr)
			prefix, err := darwinPrefix(subnet)
			require.NoError(t, err)
			request := darwinRouteMessage(unix.RTM_ADD, prefix, &net.Interface{Name: "utun7", Index: 7})
			wire, err := request.Marshal()
			require.NoError(t, err)
			messages, err := route.ParseRIB(route.RIBTypeRoute, wire)
			require.NoError(t, err)
			actual, ok := darwinMessagePrefix(messages[0].(*route.RouteMessage))
			require.True(t, ok)
			require.Equal(t, prefix, actual)
			cleanup, err := r.AddRoute(t.Context(), newMemoryDevice(), subnet)
			require.NoError(t, err)
			require.NotNil(t, cleanup)
			require.NoError(t, cleanup(t.Context()))
			require.NoError(t, cleanup(t.Context()))
			require.Equal(t, []int{unix.RTM_ADD, unix.RTM_DELETE}, *operations)
		})
	}
}

func TestDarwinIPv6ForeignAndReplacedRoutesArePreserved(t *testing.T) {
	r, messages, operations := testDarwinRouteTable()
	prefix := netip.MustParsePrefix("fd7a:203::/120")
	_, subnet, _ := net.ParseCIDR(prefix.String())
	foreign := darwinRouteMessage(unix.RTM_ADD, prefix, &net.Interface{Name: "lo0", Index: 1})
	foreign.Index = 1
	*messages = []route.Message{foreign}
	cleanup, err := r.AddRoute(t.Context(), newMemoryDevice(), subnet)
	require.ErrorIs(t, err, unix.EEXIST)
	require.Nil(t, cleanup)
	require.Empty(t, *operations)
	*messages = nil
	cleanup, err = r.AddRoute(t.Context(), newMemoryDevice(), subnet)
	require.NoError(t, err)
	message := (*messages)[0].(*route.RouteMessage)
	message.Addrs[unix.RTAX_GATEWAY] = &route.Inet6Addr{IP: netip.MustParseAddr("fd7a:203::9").As16()}
	require.ErrorContains(t, cleanup(t.Context()), "ownership")
	require.Equal(t, []int{unix.RTM_ADD}, *operations)
}

func TestDarwinIPv6AliasABIAndCanceledCall(t *testing.T) {
	request := darwinIPv6AliasRequest("utun7", netip.MustParsePrefix("fd7a:203::1/120"))
	require.Equal(t, uintptr(128), unsafe.Sizeof(request))
	require.Equal(t, uintptr(100), unsafe.Offsetof(request.Flags))
	require.Equal(t, uintptr(104), unsafe.Offsetof(request.Lifetime))
	require.Equal(t, "utun7", strings.TrimRight(string(request.Name[:]), "\x00"))
	require.Equal(t, uint8(unix.AF_INET6), request.Address.Family)
	require.Equal(t, netip.MustParseAddr("fd7a:203::1").As16(), request.Address.Addr)
	require.Equal(t, [16]byte(net.CIDRMask(120, 128)), request.Mask.Addr)
	require.Equal(t, uint32(0x20), request.Flags)
	require.Equal(t, ^uint32(0), request.Lifetime.Valid)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, addDarwinIPv6Alias(ctx, "utun7", netip.MustParsePrefix("fd7a:203::1/120")), context.Canceled)
}

type darwinAddressFixture struct {
	index     int
	addresses []netip.Prefix
	calls     []string
	failure   string
}

func darwinDualFixture(t *testing.T, failure string) (systemNetwork, darwinAddressOps, *darwinAddressFixture, CoreConfig) {
	t.Helper()
	cfg := CoreConfig{Network: "198.18.99.1/24", IPv6Network: "fd7a:203::1/120"}
	f := &darwinAddressFixture{index: 7, failure: failure, addresses: []netip.Prefix{netip.MustParsePrefix("fe80::7/64")}}
	remove := func(prefix netip.Prefix) {
		for i, address := range f.addresses {
			if address == prefix {
				f.addresses = append(f.addresses[:i], f.addresses[i+1:]...)
				return
			}
		}
	}
	ops := darwinAddressOps{identity: func(name string) (*net.Interface, error) { return &net.Interface{Name: name, Index: f.index}, nil }, prefixes: func(*net.Interface) ([]netip.Prefix, error) { return append([]netip.Prefix(nil), f.addresses...), nil }, addIPv6: func(_ context.Context, _ string, prefix netip.Prefix) error {
		f.calls = append(f.calls, "add6")
		f.addresses = append(f.addresses, prefix)
		if failure == "address6" {
			return errors.New("injected address6 failure")
		}
		return nil
	}}
	n := systemNetwork{run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		require.Equal(t, "/sbin/ifconfig", command)
		if args[len(args)-1] == "-alias" {
			prefix := netip.MustParsePrefix(args[2])
			f.calls = append(f.calls, "delete"+map[bool]string{true: "4", false: "6"}[prefix.Addr().Is4()])
			remove(prefix)
		} else {
			f.calls = append(f.calls, "add4")
			f.addresses = append(f.addresses, netip.MustParsePrefix(cfg.Network))
			if failure == "address4" {
				return nil, errors.New("injected address4 failure")
			}
		}
		return nil, nil
	}, routes: unixTestRouteOperations{add: func(_ context.Context, _ Device, prefix *net.IPNet) (Cleanup, error) {
		family := map[bool]string{true: "4", false: "6"}[prefix.IP.To4() != nil]
		f.calls = append(f.calls, "route"+family)
		cleanup := func(context.Context) error { f.calls = append(f.calls, "unroute"+family); return nil }
		if failure == "route"+family {
			return cleanup, errors.New("injected route failure")
		}
		return cleanup, nil
	}}}
	return n, ops, f, cfg
}

func TestDarwinDualStackPartialStartupRollbackAndLinkLocalPreservation(t *testing.T) {
	for _, failure := range []string{"", "address4", "address6", "route4", "route6"} {
		t.Run("failure="+failure, func(t *testing.T) {
			n, ops, state, cfg := darwinDualFixture(t, failure)
			cleanup, err := n.configureDarwinDualStack(t.Context(), newMemoryDevice(), cfg, ops)
			if failure == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "injected")
			}
			require.NotNil(t, cleanup)
			require.NoError(t, cleanup(t.Context()))
			require.NoError(t, cleanup(t.Context()))
			require.Equal(t, []netip.Prefix{netip.MustParsePrefix("fe80::7/64")}, state.addresses)
			if failure == "" {
				require.Equal(t, []string{"add4", "route4", "add6", "route6", "unroute6", "delete6", "unroute4", "delete4"}, state.calls)
			}
		})
	}
}

func TestDarwinDualStackCleanupRefusesIdentityOrPrefixReplacement(t *testing.T) {
	for _, change := range []string{"identity", "prefix"} {
		n, ops, state, cfg := darwinDualFixture(t, "")
		cleanup, err := n.configureDarwinDualStack(t.Context(), newMemoryDevice(), cfg, ops)
		require.NoError(t, err)
		if change == "identity" {
			state.index = 9
		} else {
			state.addresses[2] = netip.MustParsePrefix("fd7a:203::1/119")
		}
		err = cleanup(t.Context())
		require.ErrorContains(t, err, change)
		for _, call := range state.calls {
			require.NotEqual(t, "delete6", call)
		}
	}
}

func TestDarwinDNSListenerFamiliesAndSelfLoopGuard(t *testing.T) {
	one := syntheticIPv6Engine(t)
	require.Equal(t, "udp4", one.dns.server.Net)
	require.Equal(t, "tcp4", one.dns.tcpServer.Net)
	require.Equal(t, "[::1]:53", one.dns.ipv6.udp.Addr)
	cfg := DNSConfig{ListenPort: 53}
	core := CoreConfig{IPv6Network: "fd7a:203::1/120"}
	for _, address := range []string{"127.0.0.1:53", "[::1]:53", "[::ffff:127.0.0.1]:53", "127.0.0.1:0053", "127.0.0.1", "::1"} {
		cfg.Servers = []string{address}
		require.ErrorContains(t, validateDNSListenerUpstreams(core, cfg), "own loopback")
		cfg.Servers = nil
		cfg.Rules = []DNSRouteConfig{{Suffix: "private.test", Servers: []string{address}}}
		require.ErrorContains(t, validateDNSListenerUpstreams(core, cfg), "split DNS")
		cfg.Rules = nil
	}
	cfg.Servers = []string{"[::1]:5353", "127.0.0.1:5353"}
	require.NoError(t, validateDNSListenerUpstreams(core, cfg))
	cfg.Servers = []string{"[::1]:53"}
	require.NoError(t, validateDNSListenerUpstreams(CoreConfig{}, cfg), "IPv6 disabled means no ::1 listener to recurse into")
	for _, split := range []bool{false, true} {
		configuration := DefaultConfig()
		configuration.Core.IPv6Network = core.IPv6Network
		configuration.DNS.Servers = []string{"127.0.0.1:53"}
		message := "own loopback"
		if split {
			configuration.DNS.Servers = []string{"127.0.0.1:5353"}
			configuration.DNS.Rules = []DNSRouteConfig{{Suffix: "private.test", Servers: []string{"::1"}}}
			message = "split DNS"
		}
		engine, err := FromConfig(configuration)
		require.ErrorContains(t, err, message, "preflight must reject recursion before Run acquires any network resources")
		require.Nil(t, engine)
	}
}

type darwinSocketRaw struct{ fd int }

func (c darwinSocketRaw) Control(fn func(uintptr)) error    { fn(uintptr(c.fd)); return nil }
func (c darwinSocketRaw) Read(fn func(uintptr) bool) error  { fn(uintptr(c.fd)); return nil }
func (c darwinSocketRaw) Write(fn func(uintptr) bool) error { fn(uintptr(c.fd)); return nil }

func TestDarwinIPv6OutboundBindingUsesIPv6SocketOptionWithoutTraffic(t *testing.T) {
	// Read-only interface discovery plus a private, unconnected socket. No
	// packets, routes, interface settings or system DNS are changed.
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	raw := darwinSocketRaw{fd}
	require.NoError(t, control.BindToInterface0(nil, raw, "udp6", "[2001:4860:4860::8888]:53", lo.Name, lo.Index, false))
	bound, err := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF)
	require.NoError(t, err)
	require.Equal(t, lo.Index, bound)
}

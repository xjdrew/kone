package kone

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type resolvedFixture struct {
	dns                  *resolvedDNS
	initial, state       resolvedProfile
	calls                []string
	owner, fail          string
	index                int
	removed, failedAfter bool
	security             map[string]string
}

func resolvedEnvelope(signature string, data any) []byte {
	value, _ := json.Marshal(map[string]any{"type": signature, "data": data})
	return value
}

func newResolvedFixture() *resolvedFixture {
	f := &resolvedFixture{owner: ":1.19", index: 17, security: map[string]string{"DNSSEC": "no", "DNSOverTLS": "no"}, initial: resolvedProfile{"DNSEx": "[]", "Domains": "[]", "DefaultRoute": "false", "DNSSEC": `"no"`, "DNSOverTLS": `"no"`, "LLMNR": `"yes"`, "MulticastDNS": `"no"`, "DNSSECNegativeTrustAnchors": "[]"}}
	f.state = cloneResolvedProfile(f.initial)
	f.dns = &resolvedDNS{run: f.run, readFile: func(string) ([]byte, error) { return []byte("nameserver 127.0.0.53\n"), nil }, verifyNamespace: func(uint32) error { return nil }, lookup: func(name string) (*net.Interface, error) {
		if f.removed {
			return nil, errors.New("removed")
		}
		return &net.Interface{Name: name, Index: f.index}, nil
	}, interfaces: func() ([]net.Interface, error) {
		if f.removed {
			return nil, nil
		}
		return []net.Interface{{Name: "owned-tun", Index: f.index}}, nil
	}}
	return f
}

func (f *resolvedFixture) run(_ context.Context, tool string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, tool+" "+strings.Join(args, " "))
	if tool == "busctl" {
		methods := map[string]string{"SetLinkDNSSEC": "dnssec", "SetLinkDNSOverTLS": "dnsovertls", "SetLinkDefaultRoute": "default-route", "SetLinkDomains": "domain", "SetLinkDNSEx": "dns"}
		for i, arg := range args {
			if command, ok := methods[arg]; ok {
				value := args[len(args)-1]
				if command == "domain" || command == "dns" {
					if args[i+3] == "0" {
						value = ""
					} else if command == "domain" {
						value = "~."
					} else {
						value = "configured"
					}
				}
				args = []string{"", "", command, args[i+2], value}
				tool = "setter"
				break
			}
		}
	}
	if tool == "busctl" {
		for _, arg := range args {
			if arg == "GetNameOwner" {
				return resolvedEnvelope("s", []string{f.owner}), nil
			}
			if arg == "GetConnectionUnixProcessID" {
				return resolvedEnvelope("u", []uint32{42}), nil
			}
			if arg == "GetLink" {
				return resolvedEnvelope("o", []string{resolvedManager + "/link/escaped_17"}), nil
			}
		}
		if strings.Contains(strings.Join(args, " "), resolvedManager+"/link/escaped_17") {
			var output []byte
			for _, property := range resolvedConfigProperties {
				var value any
				_ = json.Unmarshal([]byte(f.state[property.name]), &value)
				output = append(output, resolvedEnvelope(property.signature, value)...)
				output = append(output, '\n')
			}
			return output, nil
		}
		return resolvedEnvelope("s", f.security[args[len(args)-1]]), nil
	}
	if tool != "setter" {
		return nil, errors.New("unexpected tool")
	}
	command := args[2]
	if args[3] != strconv.Itoa(17) {
		return nil, errors.New("not the owned link")
	}
	apply := func() {
		switch command {
		case "dnssec":
			value, _ := json.Marshal(args[4])
			f.state["DNSSEC"] = string(value)
		case "dnsovertls":
			value, _ := json.Marshal(args[4])
			f.state["DNSOverTLS"] = string(value)
		case "default-route":
			f.state["DefaultRoute"] = strconv.FormatBool(args[4] == "yes")
		case "dns":
			f.state["DNSEx"] = `[[2,[10,192,0,1],53,""]]`
			if args[4] == "" {
				f.state["DNSEx"] = "[]"
			}
		case "domain":
			f.state["Domains"] = `[[".",true]]`
			if args[4] == "" {
				f.state["Domains"] = "[]"
			}
		case "revert":
			f.state = cloneResolvedProfile(f.initial)
		}
	}
	if command == f.fail {
		if f.failedAfter {
			apply()
		}
		return nil, context.DeadlineExceeded
	}
	apply()
	return nil, nil
}

func (f *resolvedFixture) configure(t *testing.T) (Cleanup, error) {
	t.Helper()
	require.NoError(t, f.dns.check(context.Background()))
	return f.dns.configure(context.Background(), "owned-tun", CoreConfig{Network: "10.192.0.1/16"}, DNSConfig{System: true, ListenPort: 53}, func() error { return nil })
}

func TestSystemDNSGuidanceRestoresOnlyOwnedLink(t *testing.T) {
	f := newResolvedFixture()
	cleanup, err := f.configure(t)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	require.Equal(t, `[[".",true]]`, f.state["Domains"])
	require.Equal(t, "true", f.state["DefaultRoute"])
	require.NoError(t, cleanup(context.Background()))
	require.Equal(t, f.initial, f.state)
	for _, call := range f.calls {
		require.NotContains(t, call, "resolv.conf")
		if strings.Contains(call, " SetLink") {
			require.Contains(t, call, "--allow-interactive-authorization=no")
			require.Contains(t, call, " call :1.19 ")
			require.Contains(t, call, " 17 ")
		}
	}
}

func TestSystemDNSRestoresOnlyChangedPropertiesWithoutResettingOtherLinkPolicy(t *testing.T) {
	f := newResolvedFixture()
	f.initial["DNSSEC"] = `"allow-downgrade"`
	f.initial["DNSOverTLS"] = `"opportunistic"`
	f.initial["LLMNR"] = `"resolve"`
	f.initial["DNSSECNegativeTrustAnchors"] = `["corp.example"]`
	f.state = cloneResolvedProfile(f.initial)
	f.security["DNSSEC"] = "allow-downgrade"
	f.security["DNSOverTLS"] = "opportunistic"
	cleanup, err := f.configure(t)
	require.NoError(t, err)
	require.NoError(t, cleanup(context.Background()))
	require.Equal(t, f.initial, f.state)
	for _, call := range f.calls {
		require.NotContains(t, call, " Revert")
	}
}

func TestSystemDNSSetterFailuresRollBackIncludingAmbiguousCompletion(t *testing.T) {
	for _, command := range []string{"dnssec", "dnsovertls", "default-route", "dns", "domain"} {
		for _, after := range []bool{false, true} {
			t.Run(command+strconv.FormatBool(after), func(t *testing.T) {
				f := newResolvedFixture()
				f.fail = command
				f.failedAfter = after
				cleanup, err := f.configure(t)
				require.Error(t, err)
				require.NotNil(t, cleanup)
				f.fail = ""
				require.NoError(t, cleanup(context.Background()))
				require.Equal(t, f.initial, f.state)
			})
		}
	}
}

func TestSystemDNSPreservesExternalResolverChangesAndReusedIdentity(t *testing.T) {
	for _, change := range []string{"dns", "mode", "index", "owner", "removed"} {
		t.Run(change, func(t *testing.T) {
			f := newResolvedFixture()
			cleanup, err := f.configure(t)
			require.NoError(t, err)
			switch change {
			case "dns":
				f.state["DNSEx"] = `[[2,[192,0,2,1],53,""]]`
			case "mode":
				f.state["LLMNR"] = `"no"`
			case "index":
				f.index++
			case "owner":
				f.owner = ":1.99"
			case "removed":
				f.removed = true
			}
			before := cloneResolvedProfile(f.state)
			err = cleanup(context.Background())
			if change == "removed" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.True(t, reflect.DeepEqual(before, f.state))
		})
	}
}

func TestSystemDNSPreflightIsReadOnlyAndRejectsUnsafeResolverContext(t *testing.T) {
	f := newResolvedFixture()
	require.NoError(t, f.dns.check(context.Background()))
	for _, call := range f.calls {
		require.True(t, strings.HasPrefix(call, "busctl "))
		require.NotContains(t, call, "SetLink")
	}
	f = newResolvedFixture()
	f.dns.readFile = func(string) ([]byte, error) { return []byte("nameserver 192.0.2.1\n"), nil }
	require.ErrorContains(t, f.dns.check(context.Background()), "stub")
	require.Empty(t, f.calls)
	f = newResolvedFixture()
	f.dns.verifyNamespace = func(uint32) error { return errors.New("different namespace") }
	require.ErrorContains(t, f.dns.check(context.Background()), "namespace")
	for _, property := range []string{"DNSSEC", "DNSOverTLS"} {
		f = newResolvedFixture()
		f.security[property] = "yes"
		require.ErrorContains(t, f.dns.check(context.Background()), property)
	}
	f = newResolvedFixture()
	f.state["Domains"] = `[["corp.example",true]]`
	cleanup, err := f.configure(t)
	require.ErrorContains(t, err, "already has resolver")
	require.Nil(t, cleanup)
}

func TestSystemDNSMachineOutputAndStubBoundaries(t *testing.T) {
	for _, data := range []string{`{}`, `{"type":"u","data":[1,2]}`, `{"type":"s","data":[42]}`} {
		_, err := busJSON([]byte(data), "u", true)
		require.Error(t, err)
	}
	_, err := busJSON([]byte(strings.Repeat("x", 1<<20+1)), "s", false)
	require.Error(t, err)
	require.True(t, resolvedStubConfigured([]byte("# comment\nnameserver 127.0.0.54 # proxy stub\n")))
	require.False(t, resolvedStubConfigured([]byte("# nameserver 127.0.0.53\nnameserver 1.1.1.1\n")))
	require.False(t, resolvedStubConfigured([]byte("nameserver 127.0.0.53\nnameserver 192.0.2.1\n")))
	require.Error(t, verifyResolvedNamespace(^uint32(0)))
	_, err = (systemNetwork{}).ConfigureSystemDNS(context.Background(), &memoryDevice{}, CoreConfig{}, DNSConfig{System: true})
	require.ErrorContains(t, err, "exclusively owned")
}

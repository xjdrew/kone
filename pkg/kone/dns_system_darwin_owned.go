package kone

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
)

const darwinDNSStoreList = "list State:/Network/Service/.*/DNS\nquit\n"

func readDarwinDNSStore(ctx context.Context, script string) ([]byte, error) {
	return readDNSCommandInput(ctx, script, "/usr/sbin/scutil")
}

// The dynamic-store marker is shared across processes. A helper launched while
// the manager owns system DNS must discover the original upstreams, rather than
// sending its own recursive queries back to the manager's DNS listener.
func discoverDarwinDNSContext(ctx context.Context, data []byte, readStore func(context.Context, string) ([]byte, error)) (DNSSystemContext, error) {
	observed, err := parseDarwinDNSContext(data)
	if err != nil {
		return observed, err
	}
	loopback := false
	for _, server := range observed.DefaultServers {
		host, _, _ := net.SplitHostPort(server)
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
			loopback = true
		}
	}
	if !loopback {
		return observed, nil
	}
	fail := func(err error) (DNSSystemContext, error) {
		observed.RequireManual = true
		observed.Warnings = append(observed.Warnings, "Cannot verify macOS loopback resolver ownership; configure explicit DNS servers")
		return observed, err
	}
	if readStore == nil {
		return fail(errors.New("macOS DNS ownership discovery is unavailable"))
	}
	listing, err := readStore(ctx, darwinDNSStoreList)
	if err != nil {
		return fail(err)
	}
	keys, err := parseDarwinDNSStoreKeys(listing)
	if err != nil {
		return fail(err)
	}
	excluded := map[string]bool{}
	for _, key := range keys {
		value, err := readStore(ctx, "show "+key+"\nquit\n")
		if err != nil {
			return fail(err)
		}
		if strings.TrimSpace(string(value)) == "No such key" {
			return fail(errors.New("macOS DNS service changed during discovery"))
		}
		if !strings.Contains(string(value), "__KONEOwner") {
			continue
		}
		profile, exists, err := parseScopedDNSProfile(value)
		if err != nil || !exists {
			return fail(errors.New("macOS owned resolver profile could not be verified"))
		}
		address, err := darwinOwnedResolverAddress(key, profile)
		if err != nil {
			return fail(err)
		}
		excluded[address] = true
	}
	if len(excluded) == 0 {
		return observed, nil
	}
	filtered, err := parseDarwinDNSContextExcluding(data, excluded)
	if err != nil {
		return fail(err)
	}
	filtered.ownedDefaultExcluded = true
	if len(filtered.DefaultServers) == 0 {
		filtered.RequireManual = true
		filtered.Warnings = append(filtered.Warnings, "The original macOS default resolver is unavailable; configure explicit DNS servers")
	}
	return filtered, nil
}

func parseDarwinDNSStoreKeys(data []byte) ([]string, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("macOS DNS key listing exceeds limit")
	}
	var keys []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line == "No such key" {
			continue
		}
		_, key, found := strings.Cut(line, " = ")
		const prefix, suffix = "State:/Network/Service/", "/DNS"
		if !found || !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
			return nil, errors.New("unexpected macOS DNS key listing")
		}
		id := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
		// Third-party VPN service identifiers need not be UUIDs. Restrict only
		// their command syntax; an owned marker is checked strictly below.
		if !validDarwinDNSServiceID(id) || containsDNSValue(keys, key) || len(keys) >= 64 {
			return nil, errors.New("invalid or excessive macOS DNS service keys")
		}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("macOS DNS key listing contains oversized lines")
	}
	return keys, nil
}

func validDarwinDNSServiceID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, value := range id {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '.' || value == '_' || value == '-' {
			continue
		}
		return false
	}
	return true
}

func darwinOwnedResolverAddress(key string, profile scopedDNSProfile) (string, error) {
	one := func(name string) string {
		if values := profile[name]; len(values) == 1 {
			return values[0]
		}
		return ""
	}
	id, device := one("__KONEOwner"), one("__KONEInterface")
	port, err := strconv.ParseUint(one("ServerPort"), 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("macOS owned resolver has an invalid port")
	}
	address := netip.MustParseAddr("127.0.0.1")
	expectedKey, _, expected, err := scopedDNSScript(id, device, address, uint16(port))
	if err != nil || expectedKey != key || !reflect.DeepEqual(profile, expected) {
		return "", errors.New("macOS owned resolver identity or settings changed")
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(port))), nil
}

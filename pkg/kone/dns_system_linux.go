package kone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
)

const resolvedService = "org.freedesktop.resolve1"
const resolvedManager = "/org/freedesktop/resolve1"
const resolvedLinkInterface = "org.freedesktop.resolve1.Link"

type resolvedProperty struct{ name, signature string }

var resolvedConfigProperties = []resolvedProperty{
	{"DNSEx", "a(iayqs)"}, {"Domains", "a(sb)"}, {"DefaultRoute", "b"},
	{"DNSSEC", "s"}, {"DNSOverTLS", "s"}, {"LLMNR", "s"}, {"MulticastDNS", "s"}, {"DNSSECNegativeTrustAnchors", "as"},
}

type resolvedProfile map[string]string

type resolvedDNS struct {
	run             commandRunner
	lookup          func(string) (*net.Interface, error)
	interfaces      func() ([]net.Interface, error)
	readFile        func(string) ([]byte, error)
	verifyNamespace func(uint32) error
	owner           string
}

func SupportsSystemDNS() bool { return true }

func newResolvedDNS(run commandRunner) *resolvedDNS {
	return &resolvedDNS{run: run, lookup: net.InterfaceByName, interfaces: net.Interfaces, readFile: readSystemResolverFile, verifyNamespace: verifyResolvedNamespace}
}

func readSystemResolverFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 1<<20+1))
}

func CheckSystemDNS(ctx context.Context, cfg DNSConfig) error {
	if !cfg.System {
		return nil
	}
	return newResolvedDNS(runCommand).check(ctx)
}

func (n systemNetwork) ConfigureSystemDNS(ctx context.Context, device Device, core CoreConfig, cfg DNSConfig) (Cleanup, error) {
	if !cfg.System {
		return nil, nil
	}
	owned, ok := device.(*singDevice)
	if !ok || owned == nil || isNilInterface(owned.Tun) {
		return nil, errors.New("system DNS requires an exclusively owned live TUN device")
	}
	dns := newResolvedDNS(n.run)
	if err := dns.check(ctx); err != nil {
		return nil, err
	}
	return dns.configure(ctx, device.Name(), core, cfg, func() error {
		name, err := owned.Tun.Name() // TUNGETIFF uses the open device, not a guessed name.
		if err != nil {
			return err
		}
		if name != device.Name() {
			return errors.New("owned TUN identity changed")
		}
		return nil
	})
}

func busJSON(data []byte, signature string, call bool) (json.RawMessage, error) {
	var envelope struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if len(data) > 1<<20 || json.Unmarshal(data, &envelope) != nil || envelope.Type != signature {
		return nil, errors.New("unexpected systemd-resolved D-Bus response")
	}
	if call {
		var values []json.RawMessage
		if json.Unmarshal(envelope.Data, &values) != nil || len(values) != 1 {
			return nil, errors.New("invalid D-Bus method result")
		}
		return values[0], nil
	}
	return envelope.Data, nil
}

func (d *resolvedDNS) bus(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{"--system", "--no-pager", "--auto-start=no", "--allow-interactive-authorization=no", "--json=short"}
	return d.run(ctx, "busctl", append(base, args...)...)
}

func (d *resolvedDNS) set(ctx context.Context, index int, command, argument string) error {
	idx := strconv.Itoa(index)
	var method, signature string
	var values []string
	switch command {
	case "dnssec":
		method, signature, values = "SetLinkDNSSEC", "is", []string{idx, argument}
	case "dnsovertls":
		method, signature, values = "SetLinkDNSOverTLS", "is", []string{idx, argument}
	case "default-route":
		method, signature, values = "SetLinkDefaultRoute", "ib", []string{idx, argument}
	case "domain":
		method, signature = "SetLinkDomains", "ia(sb)"
		values = []string{idx, "0"}
		if argument != "" {
			if argument != "~." {
				return errors.New("unsupported owned DNS routing domain")
			}
			values = []string{idx, "1", ".", "true"}
		}
	case "dns":
		method, signature = "SetLinkDNSEx", "ia(iayqs)"
		values = []string{idx, "0"}
		if argument != "" {
			address, err := netip.ParseAddrPort(argument)
			if err != nil || !address.Addr().Is4() {
				return errors.New("invalid owned DNS endpoint")
			}
			values = []string{idx, "1", "2", "4"}
			for _, value := range address.Addr().AsSlice() {
				values = append(values, strconv.Itoa(int(value)))
			}
			values = append(values, strconv.Itoa(int(address.Port())), "")
		}
	default:
		return errors.New("unsupported resolver setter")
	}
	_, err := d.bus(ctx, append([]string{"call", resolvedService, resolvedManager, "org.freedesktop.resolve1.Manager", method, signature}, values...)...)
	return err
}

func (d *resolvedDNS) realm(ctx context.Context) (string, error) {
	data, err := d.bus(ctx, "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", resolvedService)
	if err != nil {
		return "", fmt.Errorf("systemd-resolved is unavailable: %w", err)
	}
	value, err := busJSON(data, "s", true)
	var owner string
	if err != nil || json.Unmarshal(value, &owner) != nil || !strings.HasPrefix(owner, ":") {
		return "", errors.New("cannot verify the systemd-resolved owner")
	}
	data, err = d.bus(ctx, "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID", "s", owner)
	if err != nil {
		return "", err
	}
	value, err = busJSON(data, "u", true)
	var pid uint32
	if err != nil || json.Unmarshal(value, &pid) != nil || pid == 0 {
		return "", errors.New("cannot verify systemd-resolved process identity")
	}
	if err := d.verifyNamespace(pid); err != nil {
		return "", err
	}
	return owner, nil
}

func verifyResolvedNamespace(pid uint32) error {
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	resolver, err := os.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/ns/net")
	if err != nil {
		return fmt.Errorf("cannot verify resolver network namespace: %w", err)
	}
	if !os.SameFile(self, resolver) {
		return errors.New("systemd-resolved belongs to a different network namespace; refusing to modify host DNS")
	}
	return nil
}

func resolvedStubConfigured(data []byte) bool {
	if len(data) > 1<<20 {
		return false
	}
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0])
		if len(fields) > 0 && fields[0] == "nameserver" {
			if len(fields) < 2 || fields[1] != "127.0.0.53" && fields[1] != "127.0.0.54" {
				return false
			}
			seen = true
		}
	}
	return seen
}

func (d *resolvedDNS) check(ctx context.Context) error {
	data, err := d.readFile("/etc/resolv.conf")
	if err != nil || !resolvedStubConfigured(data) {
		return errors.New("dns.system requires applications to already use the systemd-resolved stub; configure the OS resolver first or disable this option; KONE never rewrites resolv.conf")
	}
	owner, err := d.realm(ctx)
	if err != nil {
		return err
	}
	d.owner = owner
	for _, property := range []string{"DNSSEC", "DNSOverTLS"} {
		data, err = d.bus(ctx, "get-property", resolvedService, resolvedManager, "org.freedesktop.resolve1.Manager", property)
		if err != nil {
			return fmt.Errorf("inspect system resolver security: %w", err)
		}
		value, err := busJSON(data, "s", false)
		var mode string
		if err != nil || json.Unmarshal(value, &mode) != nil {
			return errors.New("invalid resolver security policy")
		}
		if mode == "yes" {
			return fmt.Errorf("dns.system cannot preserve strict system %s policy; use explicit OS/VPN DNS integration", property)
		}
	}
	return nil
}

func (d *resolvedDNS) profile(ctx context.Context, index int) (resolvedProfile, error) {
	args := []string{"get-property", resolvedService, resolvedManager + "/link/_" + strconv.Itoa(index), resolvedLinkInterface}
	for _, property := range resolvedConfigProperties {
		args = append(args, property.name)
	}
	data, err := d.bus(ctx, args...)
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("resolver link profile exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	profile := resolvedProfile{}
	for _, property := range resolvedConfigProperties {
		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if decoder.Decode(&envelope) != nil || envelope.Type != property.signature {
			return nil, errors.New("invalid resolver link configuration")
		}
		var value any
		if json.Unmarshal(envelope.Data, &value) != nil {
			return nil, errors.New("invalid resolver property")
		}
		if property.name == "DNSEx" {
			// resolved may encode the ordinary DNS port as zero (the default).
			if servers, ok := value.([]any); ok {
				for _, entry := range servers {
					if fields, ok := entry.([]any); ok && len(fields) == 4 && fields[2] == float64(0) {
						fields[2] = float64(53)
					}
				}
			}
		}
		canonical, _ := json.Marshal(value)
		profile[property.name] = string(canonical)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("unexpected resolver properties")
	}
	return profile, nil
}

func cloneResolvedProfile(profile resolvedProfile) resolvedProfile {
	out := resolvedProfile{}
	for key, value := range profile {
		out[key] = value
	}
	return out
}

func (d *resolvedDNS) configure(ctx context.Context, name string, core CoreConfig, cfg DNSConfig, verifyOwned func() error) (Cleanup, error) {
	device, err := d.lookup(name)
	if err != nil || device == nil || device.Index <= 0 {
		return nil, errors.New("cannot inspect owned DNS link")
	}
	index := device.Index
	if err := verifyOwned(); err != nil {
		return nil, err
	}
	owner, err := d.realm(ctx)
	if err != nil || owner != d.owner {
		return nil, errors.New("resolver instance changed before configuring DNS")
	}
	initial, err := d.profile(ctx, index)
	if err != nil {
		return nil, fmt.Errorf("inspect new TUN resolver settings: %w", err)
	}
	if initial["DNSEx"] != "[]" || initial["Domains"] != "[]" {
		return nil, errors.New("new TUN already has resolver configuration; refusing to overwrite it")
	}
	ip, err := netip.ParsePrefix(core.Network)
	if err != nil || !ip.Addr().Is4() {
		return nil, errors.New("invalid TUN DNS address")
	}
	address := ip.Addr().As4()
	data, _ := json.Marshal([]any{[]any{2, []int{int(address[0]), int(address[1]), int(address[2]), int(address[3])}, cfg.ListenPort, ""}})
	target := net.JoinHostPort(ip.Addr().String(), strconv.Itoa(int(cfg.ListenPort)))
	allowed := []resolvedProfile{cloneResolvedProfile(initial)}
	cleanup := func(ctx context.Context) error {
		currentDevice, e := d.lookup(name)
		if e != nil { // A removed link automatically loses resolved configuration.
			interfaces, inspectErr := d.interfaces()
			if inspectErr != nil {
				return inspectErr
			}
			for _, item := range interfaces {
				if item.Index == index || item.Name == name {
					return errors.New("cannot verify resolver link removal")
				}
			}
			return nil
		}
		if currentDevice == nil || currentDevice.Index != index {
			return errors.New("DNS link identity was reused; external settings preserved")
		}
		if e := verifyOwned(); e != nil {
			return fmt.Errorf("cannot verify owned DNS device: %w", e)
		}
		owner, e := d.realm(ctx)
		if e != nil || owner != d.owner {
			return errors.New("resolver instance changed; external DNS settings preserved")
		}
		current, e := d.profile(ctx, index)
		if e != nil {
			return e
		}
		owned := false
		for _, expected := range allowed {
			if reflect.DeepEqual(current, expected) {
				owned = true
				break
			}
		}
		if !owned {
			return errors.New("resolver link was modified externally; new DNS settings preserved")
		}
		// Restore only the five properties we changed. A blanket `revert` also
		// resets LLMNR/mDNS/NTAs that a network manager may have configured.
		for _, restore := range []struct{ property, command, argument string }{
			{"Domains", "domain", ""}, {"DNSEx", "dns", ""}, {"DefaultRoute", "default-route", map[bool]string{true: "yes", false: "no"}[initial["DefaultRoute"] == "true"]},
			{"DNSOverTLS", "dnsovertls", strings.Trim(initial["DNSOverTLS"], `"`)}, {"DNSSEC", "dnssec", strings.Trim(initial["DNSSEC"], `"`)},
		} {
			if current[restore.property] == initial[restore.property] {
				continue
			}
			expected := cloneResolvedProfile(current)
			expected[restore.property] = initial[restore.property]
			allowed = append(allowed, expected)
			if e = d.set(ctx, index, restore.command, restore.argument); e != nil {
				return e
			}
			current = expected
		}
		return nil
	}
	steps := []struct{ property, value, command, argument string }{
		{"DNSSEC", `"no"`, "dnssec", "no"}, {"DNSOverTLS", `"no"`, "dnsovertls", "no"},
		{"DefaultRoute", "true", "default-route", "yes"}, {"DNSEx", string(data), "dns", target}, {"Domains", `[[".",true]]`, "domain", "~."},
	}
	expected := cloneResolvedProfile(initial)
	for _, step := range steps {
		if err := verifyOwned(); err != nil {
			return cleanup, err
		}
		profile, err := d.profile(ctx, index)
		if err != nil || !reflect.DeepEqual(profile, expected) {
			return cleanup, errors.New("resolver link changed during DNS setup; external settings preserved")
		}
		expected = cloneResolvedProfile(expected)
		expected[step.property] = step.value
		allowed = append(allowed, expected) // A setter can complete before its timeout is reported.
		if err := d.set(ctx, index, step.command, step.argument); err != nil {
			return cleanup, fmt.Errorf("configure owned resolver %s: %w", step.command, err)
		}
	}
	current, err := d.profile(ctx, index)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return cleanup, errors.New("owned resolver settings did not match the requested configuration")
	}
	return cleanup, nil
}

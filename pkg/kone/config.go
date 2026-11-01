package kone

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/dnsconfig"
	"github.com/xjdrew/kone/pkg/proxy"
)

const (
	HTTP_PROXY  = "http_proxy"
	HTTPS_PROXY = "https_proxy"
	SOCKS_PROXY = "socks_proxy"
)

type GeneralConfig struct {
	LogLevel  string `toml:"log-level"`
	LogFormat string `toml:"log-format"`
}

type CoreConfig struct {
	Tun               string `toml:"tun"`
	Stack             string `toml:"stack"`
	AutoRoute         bool   `toml:"auto-route"`
	OutboundInterface string `toml:"outbound-interface"`
	Network           string `toml:"network"`
	IPv6Network       string `toml:"ipv6-network"`
	AutoRoute6        bool   `toml:"auto-route6"`
}

type DNSConfig struct {
	System           bool             `toml:"system"`
	ListenPort       uint16           `toml:"listen-port"`
	TTL              uint             `toml:"ttl"`
	PacketSize       uint16           `toml:"packet-size"`
	ReadTimeout      uint             `toml:"read-timeout"`
	WriteTimeout     uint             `toml:"write-timeout"`
	Servers          []string         `toml:"servers,omitempty"`
	HistoryLimit     uint             `toml:"history-limit"`
	HistoryRetention uint             `toml:"history-retention"`
	CacheLimit       uint             `toml:"cache-limit"`
	Rules            []DNSRouteConfig `toml:"rules,omitempty"`
	SystemContext    DNSSystemContext `toml:"-"`
}

type DNSRouteConfig struct {
	Suffix      string   `toml:"suffix" json:"suffix"`
	Servers     []string `toml:"servers" json:"servers"`
	Interface   string   `toml:"interface,omitempty" json:"interface,omitempty"`
	Automatic   bool     `toml:"-" json:"automatic,omitempty"`
	Exact       bool     `toml:"-" json:"exact,omitempty"`
	Unavailable bool     `toml:"-" json:"unavailable,omitempty"`
	Reason      string   `toml:"-" json:"reason,omitempty"`
}

type OutboundType string

const (
	OutboundProxy  OutboundType = "proxy"
	OutboundDirect OutboundType = "direct"
	OutboundReject OutboundType = "reject"
	// BuiltinDirect and BuiltinReject are always available rule targets.
	BuiltinDirect = string(OutboundDirect)
	BuiltinReject = string(OutboundReject)
)

type OutboundConfig struct {
	ID          string `toml:"id,omitempty"`
	Enabled     *bool  `toml:"enabled,omitempty"`
	Name        string `toml:"name"`
	URL         string `toml:"url"`
	UDPFallback string `toml:"udp-fallback,omitempty"`
}

func builtinOutbounds() map[string]OutboundType {
	return map[string]OutboundType{
		BuiltinDirect: OutboundDirect,
		BuiltinReject: OutboundReject,
	}
}

type RuleConfig struct {
	ExpiresAt string   `toml:"expires-at,omitempty"`
	ID        string   `toml:"id,omitempty"`
	Source    string   `toml:"source,omitempty"`
	Protocol  string   `toml:"protocol,omitempty"`
	Ports     []uint16 `toml:"ports,omitempty"`
	Schema    string   `toml:"type"`
	Pattern   string   `toml:"pattern,omitempty"`
	Outbound  string   `toml:"outbound"`
}

type KoneConfig struct {
	source    any
	General   GeneralConfig    `toml:"general"`
	Core      CoreConfig       `toml:"core"`
	DNS       DNSConfig        `toml:"dns"`
	GeoIP     GeoIPConfig      `toml:"geoip"`
	Outbounds []OutboundConfig `toml:"outbounds"`
	Rule      []RuleConfig     `toml:"rules"`
}

func defaultConfig() *KoneConfig {
	return &KoneConfig{
		General: GeneralConfig{LogLevel: "info", LogFormat: "text"},
		Core:    CoreConfig{Network: "10.192.0.1/16", Stack: "system"},
		GeoIP:   GeoIPConfig{Provider: "builtin"},
		DNS: DNSConfig{ListenPort: DnsDefaultPort, TTL: DnsDefaultTtl, PacketSize: DnsDefaultPacketSize,
			ReadTimeout: DnsDefaultReadTimeout, WriteTimeout: DnsDefaultWriteTimeout, HistoryLimit: 512, HistoryRetention: 3600, CacheLimit: 1024},
	}
}

// ParseConfig reads a TOML filename or a copy of TOML bytes. Unknown keys are
// errors; a misspelled option never silently uses a default.
func ParseConfig(source any) (*KoneConfig, error) { return parseConfig(source, true) }

// ParseManagedConfig never imports terminal proxy environment variables.
// Desktop settings are explicit, durable and independent of the launch shell.
func ParseManagedConfig(source any) (*KoneConfig, error) { return parseConfig(source, false) }

func DefaultConfig() *KoneConfig { return cloneConfig(defaultConfig()) }

func parseConfig(source any, environment bool) (*KoneConfig, error) {
	var data []byte
	var err error
	switch v := source.(type) {
	case string:
		data, err = os.ReadFile(v)
	case []byte:
		data = bytes.Clone(v)
	default:
		return nil, errors.New("config source must be a filename or TOML bytes")
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := defaultConfig()
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(cfg); err != nil {
		// Parser excerpts can contain credentials. Report key/position only.
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			for _, item := range strict.Errors {
				if slices.Equal(item.Key(), []string{"general", "manager-addr"}) {
					return nil, errors.New("general.manager-addr was removed; delete this option and use -manage for the password-protected Web console (file mode has no management listener)")
				}
			}
			if len(strict.Errors) > 0 {
				item := strict.Errors[0]
				line, col := item.Position()
				return nil, fmt.Errorf("decode TOML: unknown configuration key %q at line %d, column %d", strings.Join(item.Key(), "."), line, col)
			}
			return nil, errors.New("decode TOML: unknown configuration key")
		}
		var decode *toml.DecodeError
		if errors.As(err, &decode) {
			line, col := decode.Position()
			return nil, fmt.Errorf("decode TOML at line %d, column %d: invalid syntax or value", line, col)
		}
		return nil, errors.New("decode TOML: invalid configuration")
	}
	if filename, ok := source.(string); ok {
		cfg.source = filename
	} else {
		cfg.source = data
	}
	if _, err := validateOutbounds(cfg.Outbounds); err != nil {
		return nil, err
	}
	for _, key := range []string{HTTP_PROXY, HTTPS_PROXY, SOCKS_PROXY} {
		if !environment {
			break
		}
		value := os.Getenv(key)
		if value == "" {
			value = os.Getenv(strings.ToUpper(key))
		}
		if value != "" {
			found := false
			for i := range cfg.Outbounds {
				if cfg.Outbounds[i].Name == key {
					cfg.Outbounds[i].URL = value
					found = true
					break
				}
			}
			if !found {
				cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{Name: key, URL: value})
			}
		}
	}
	for i, addr := range cfg.DNS.Servers {
		normalized, err := normalizeDNSServer(addr)
		if err != nil {
			return nil, fmt.Errorf("dns.servers[%d]: %w", i+1, err)
		}
		cfg.DNS.Servers[i] = normalized
	}
	if len(cfg.DNS.Servers) == 0 {
		cfg.DNS.Servers = nil // omitted and explicitly empty both mean automatic
	}
	for i := range cfg.DNS.Rules {
		cfg.DNS.Rules[i].Suffix = normalizeDNSSuffix(cfg.DNS.Rules[i].Suffix)
		for j, addr := range cfg.DNS.Rules[i].Servers {
			normalized, err := normalizeDNSServer(addr)
			if err != nil {
				return nil, fmt.Errorf("dns.rules[%d].servers[%d]: %w", i+1, j+1, err)
			}
			cfg.DNS.Rules[i].Servers[j] = normalized
		}
	}
	for i := range cfg.Rule {
		cfg.Rule[i].Schema = strings.ToUpper(cfg.Rule[i].Schema)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !environment && cfg.GeoIP.File != "" {
		return nil, errors.New("managed mode uses the GeoIP dataset panel; local geoip.file paths are supported only in CLI file mode")
	}
	return cfg, nil
}

func validateOutbounds(config []OutboundConfig) (map[string]OutboundType, error) {
	ids := map[string]bool{}
	types := builtinOutbounds()
	for i, o := range config {
		if o.ID != "" {
			if ids[o.ID] || len(o.ID) > 128 || strings.ContainsAny(o.ID, "\x00\r\n\t ") {
				return nil, fmt.Errorf("outbounds[%d]: id must be unique and contain no whitespace or control characters", i+1)
			}
			ids[o.ID] = true
		}
		fail := func(reason string) error { return fmt.Errorf("outbounds[%d]: %s", i+1, reason) }
		if o.Name == "" || strings.TrimSpace(o.Name) != o.Name || strings.ContainsAny(o.Name, "\x00\r\n\t") {
			return nil, fail("name must be nonempty with no surrounding whitespace or control characters")
		}
		for name := range builtinOutbounds() {
			if strings.EqualFold(o.Name, name) {
				return nil, fail("name is reserved for built-in outbound " + name)
			}
		}
		if _, exists := types[o.Name]; exists {
			return nil, fail("duplicate outbound name " + o.Name)
		}
		if _, err := proxy.FromUrl(o.URL); err != nil {
			return nil, fail("invalid proxy URL (expected http, https, socks5 or ss with host and port)")
		}
		// Keep fallback targets terminal: never recurse through another
		// unsupported proxy or a cycle.
		if o.UDPFallback != "" && o.UDPFallback != BuiltinDirect && o.UDPFallback != BuiltinReject {
			return nil, fail("udp-fallback must be direct or reject")
		}
		types[o.Name] = OutboundProxy
	}
	return types, nil
}

// Resolve automatic upstreams before opening the TUN, while preserving the
// empty configured list so reload cannot rediscover our own virtual DNS.
func effectiveDNSConfig(cfg DNSConfig, read func() ([]string, error)) (DNSConfig, error) {
	cfg.Servers = slices.Clone(cfg.Servers)
	if len(cfg.Servers) == 0 {
		servers, err := read()
		if err != nil {
			return cfg, fmt.Errorf("read system DNS: %w (set dns.servers explicitly)", err)
		}
		cfg.Servers = slices.Clone(servers)
	}
	if len(cfg.Servers) == 0 {
		return cfg, errors.New("no system DNS servers found; set dns.servers explicitly")
	}
	for i, server := range cfg.Servers {
		value, err := normalizeDNSServer(server)
		if err != nil {
			return cfg, fmt.Errorf("dns.servers[%d]: %w", i+1, err)
		}
		cfg.Servers[i] = value
	}
	return cfg, nil
}

func systemDNSServers() ([]string, error) {
	config := dnsconfig.ReadDnsConfig()
	return config.Servers, config.Err
}

func normalizeDNSServer(value string) (string, error) {
	if ip, err := netip.ParseAddr(value); err == nil {
		if ip.Zone() != "" && !ip.IsLinkLocalUnicast() {
			return "", errors.New("DNS address zones are allowed only for link-local IPv6")
		}
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("expected an IP address, optionally with a port")
	}
	if ip, err := netip.ParseAddr(host); err != nil {
		return "", errors.New("DNS server must be an IP address")
	} else if ip.Zone() != "" && !ip.IsLinkLocalUnicast() {
		return "", errors.New("DNS address zones are allowed only for link-local IPv6")
	}
	if err := validatePort(port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

func validatePort(value string) error {
	p, err := strconv.Atoi(value)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

// Validate runs before a device is created or any system routes are changed.
func (cfg *KoneConfig) Validate() error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if err := cfg.GeoIP.Validate(); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cfg.Core.Network)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return errors.New("core.network must be an IPv4 host/prefix with prefix length 8..30")
	}
	if !prefix.Addr().IsGlobalUnicast() || prefix.Addr() == prefix.Masked().Addr() || prefix.Addr() == broadcastAddress(prefix) {
		return errors.New("core.network must be a unicast host address, not the network or broadcast address")
	}
	if !prefix.Contains(prefix.Addr().Next()) || prefix.Addr().Next() == broadcastAddress(prefix) {
		return errors.New("core.network must leave one additional host address for the TUN stack")
	}
	prefix6 := netip.Prefix{}
	if cfg.Core.IPv6Network != "" {
		prefix6, err = netip.ParsePrefix(cfg.Core.IPv6Network)
		if err != nil || !prefix6.Addr().Is6() || prefix6.Addr().Is4In6() || !prefix6.Addr().IsPrivate() || prefix6.Bits() < 64 || prefix6.Bits() > 120 || prefix6.Addr() == prefix6.Masked().Addr() || !prefix6.Contains(prefix6.Addr().Next()) {
			return errors.New("core.ipv6-network requires a ULA IPv6 host/prefix of length 64..120 with room for the next stack address")
		}
	}
	if cfg.Core.AutoRoute6 && (!prefix6.IsValid() || cfg.Core.OutboundInterface == "") {
		return errors.New("core.auto-route6 requires core.ipv6-network and core.outbound-interface")
	}
	if strings.ContainsAny(cfg.Core.Tun, "\x00\r\n\t\"' ") {
		return errors.New("core.tun contains unsupported characters")
	}
	if !slices.Contains(SupportedStacks(), cfg.Core.Stack) {
		return errors.New("core.stack must be system, gvisor or mixed")
	}
	if strings.ContainsAny(cfg.Core.OutboundInterface, "\x00\r\n\t\"'") {
		return errors.New("core.outbound-interface contains unsupported characters")
	}
	if cfg.Core.AutoRoute && cfg.Core.OutboundInterface == "" {
		return errors.New("core.auto-route requires core.outbound-interface to prevent routing loops")
	}
	if cfg.Core.OutboundInterface != "" && cfg.Core.OutboundInterface == cfg.Core.Tun {
		return errors.New("core.outbound-interface must differ from core.tun")
	}
	if _, err := logLevel(cfg.General.LogLevel); err != nil {
		return err
	}
	if cfg.General.LogFormat != "text" && cfg.General.LogFormat != "json" {
		return errors.New("general.log-format must be text or json")
	}
	if cfg.DNS.ListenPort == 0 {
		return errors.New("dns.listen-port must be nonzero")
	}
	if cfg.DNS.TTL == 0 || cfg.DNS.TTL > math.MaxUint32 {
		return errors.New("dns.ttl must be between 1 and 4294967295 seconds")
	}
	if cfg.DNS.PacketSize < 512 {
		return errors.New("dns.packet-size must be at least 512 bytes")
	}
	if cfg.DNS.ReadTimeout == 0 || cfg.DNS.ReadTimeout > 300 || cfg.DNS.WriteTimeout == 0 || cfg.DNS.WriteTimeout > 300 {
		return errors.New("dns read/write timeouts must be between 1 and 300 seconds")
	}
	if cfg.DNS.HistoryLimit > 10000 || cfg.DNS.CacheLimit > 10000 {
		return errors.New("dns history-limit and cache-limit must be between 0 and 10000")
	}
	if cfg.DNS.HistoryRetention == 0 || cfg.DNS.HistoryRetention > 86400 {
		return errors.New("dns.history-retention must be between 1 and 86400 seconds")
	}
	if len(cfg.DNS.Servers) > 16 || len(cfg.DNS.Rules) > 64 {
		return errors.New("DNS accepts at most 16 default servers and 64 split rules")
	}
	for i, server := range cfg.DNS.Servers {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return fmt.Errorf("dns.servers[%d]: %w", i+1, err)
		}
		host, _, _ := net.SplitHostPort(normalized)
		ip, _ := netip.ParseAddr(host)
		if ip.IsUnspecified() || ip.IsMulticast() || prefix.Contains(ip) || prefix6.IsValid() && prefix6.Contains(ip) {
			return fmt.Errorf("dns.servers[%d] is invalid or routed into the virtual network", i+1)
		}
	}
	seenDNSSuffixes := make(map[string]bool)
	for i, route := range cfg.DNS.Rules {
		suffix := normalizeDNSSuffix(route.Suffix)
		key := dnsRouteKey(route)
		if !validDNSSuffix(suffix) || seenDNSSuffixes[key] || len(route.Servers) == 0 && !(route.Automatic && route.Unavailable) || len(route.Servers) > 16 {
			return fmt.Errorf("dns.rules[%d] requires a unique valid suffix and at least one server", i+1)
		}
		seenDNSSuffixes[key] = true
		if len(route.Interface) > 256 || strings.TrimSpace(route.Interface) != route.Interface || strings.ContainsAny(route.Interface, "\x00\r\n\t\"'") || route.Interface != "" && route.Interface == cfg.Core.Tun {
			return fmt.Errorf("dns.rules[%d].interface is invalid or names the TUN", i+1)
		}
		for j, server := range route.Servers {
			normalized, err := normalizeDNSServer(server)
			if err != nil {
				return fmt.Errorf("dns.rules[%d].servers[%d]: %w", i+1, j+1, err)
			}
			host, _, _ := net.SplitHostPort(normalized)
			ip, _ := netip.ParseAddr(host)
			if ip.IsUnspecified() || ip.IsMulticast() || prefix.Contains(ip) || prefix6.IsValid() && prefix6.Contains(ip) {
				return fmt.Errorf("dns.rules[%d].servers[%d] is invalid or routed into the virtual network", i+1, j+1)
			}
		}
	}
	types, err := validateOutbounds(cfg.Outbounds)
	if err != nil {
		return err
	}
	ruleIDs := map[string]bool{}
	for i, r := range cfg.Rule {
		fail := func(reason string) error { return fmt.Errorf("rules[%d]: %s", i+1, reason) }
		if r.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, r.ExpiresAt); err != nil {
				return fail("expires-at must be an RFC3339 timestamp")
			}
			switch strings.ToUpper(r.Schema) {
			case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
			default:
				return fail("temporary rules support domain targets only; capture routes need an explicit restart")
			}
		}
		if r.ID != "" {
			if ruleIDs[r.ID] || len(r.ID) > 128 || strings.ContainsAny(r.ID, "\x00\r\n\t ") {
				return fail("id must be unique and contain no whitespace or control characters")
			}
			ruleIDs[r.ID] = true
		}
		if r.Protocol != "" && r.Protocol != "tcp" && r.Protocol != "udp" {
			return fail("protocol must be tcp or udp")
		}
		for _, port := range r.Ports {
			if port == 0 {
				return fail("ports must be between 1 and 65535")
			}
		}
		if len(r.Ports) > 128 {
			return fail("too many ports")
		}
		if len(r.Source) > 128 || strings.ContainsAny(r.Source, "\x00\r\n") {
			return fail("invalid source")
		}
		if _, ok := types[r.Outbound]; !ok {
			return fail("references undefined outbound " + r.Outbound)
		}
		switch strings.ToUpper(r.Schema) {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
			if r.Pattern == "" || strings.ContainsAny(r.Pattern, " \t\r\n") {
				return fail("domain pattern must be nonempty and contain no whitespace")
			}
		case "IP-CIDR":
			p, err := netip.ParsePrefix(r.Pattern)
			if err != nil || !p.Addr().Is4() {
				return fail("IP-CIDR requires an IPv4 prefix")
			}
			if p.Bits() == 0 && types[r.Outbound] != OutboundDirect && cfg.Core.OutboundInterface == "" {
				return fail("a default capture route requires core.outbound-interface; prefer core.auto-route")
			}
		case "IP-CIDR6":
			p, err := netip.ParsePrefix(r.Pattern)
			if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
				return fail("IP-CIDR6 requires an IPv6 prefix")
			}
			if !prefix6.IsValid() {
				return fail("IPv6 interception is not supported without core.ipv6-network")
			}
			if p.Bits() == 0 && types[r.Outbound] != OutboundDirect && cfg.Core.OutboundInterface == "" {
				return fail("an IPv6 default capture route requires core.outbound-interface")
			}
		case "GEOIP":
			if len(r.Pattern) != 2 || r.Pattern[0] < 'A' || r.Pattern[0] > 'Z' || r.Pattern[1] < 'A' || r.Pattern[1] > 'Z' {
				return fail("GEOIP requires a two-letter uppercase country code")
			}
		case "FINAL":
			if r.Pattern != "" || i != len(cfg.Rule)-1 {
				return fail("FINAL must be last and have no pattern")
			}
		default:
			return fail("unknown rule type " + r.Schema)
		}
	}
	return nil
}

func broadcastAddress(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= math.MaxUint32 >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func logLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, errors.New("general.log-level must be debug, info, warn or error")
}

// ConfigureLogging installs the application's structured slog handler.
func ConfigureLogging(w io.Writer, cfg GeneralConfig, debug bool) error {
	handler, err := NewLoggingHandler(w, cfg, debug)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(handler).With("service", "kone"))
	return nil
}

// NewLoggingHandler creates a handler without changing another instance's logger.
// Callers can attach their own bounded history before installing it.
func NewLoggingHandler(w io.Writer, cfg GeneralConfig, debug bool) (slog.Handler, error) {
	level, err := logLevel(cfg.LogLevel)
	if err != nil {
		return nil, err
	}
	if debug {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.LogFormat {
	case "text":
		handler = slog.NewTextHandler(w, opts)
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	default:
		return nil, errors.New("general.log-format must be text or json")
	}
	return handler, nil
}

// RedactedTOML returns the effective configuration without proxy credentials.
func (cfg *KoneConfig) RedactedTOML() ([]byte, error) {
	copy := *cfg
	copy.Outbounds = slices.Clone(cfg.Outbounds)
	for i, outbound := range cfg.Outbounds {
		if outbound.URL == "" {
			continue
		}
		u, err := url.Parse(outbound.URL)
		if err != nil {
			copy.Outbounds[i].URL = "REDACTED"
			continue
		}
		if u.User != nil {
			u.User = url.UserPassword("REDACTED", "REDACTED")
		}
		copy.Outbounds[i].URL = u.String()
	}
	return toml.Marshal(&copy)
}

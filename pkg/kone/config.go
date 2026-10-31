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

	"github.com/pelletier/go-toml/v2"
	singtun "github.com/sagernet/sing-tun"
	"github.com/xjdrew/kone/pkg/dnsconfig"
	"github.com/xjdrew/kone/pkg/proxy"
)

const (
	HTTP_PROXY  = "http_proxy"
	HTTPS_PROXY = "https_proxy"
	SOCKS_PROXY = "socks_proxy"
)

type GeneralConfig struct {
	ManagerAddr string `toml:"manager-addr"`
	LogLevel    string `toml:"log-level"`
	LogFormat   string `toml:"log-format"`
}

type CoreConfig struct {
	Tun               string `toml:"tun"`
	Stack             string `toml:"stack"`
	AutoRoute         bool   `toml:"auto-route"`
	OutboundInterface string `toml:"outbound-interface"`
	Network           string `toml:"network"`
	TcpListenPort     uint16 `toml:"tcp-listen-port"`
	TcpNatPortStart   uint16 `toml:"tcp-nat-port-start"`
	TcpNatPortEnd     uint16 `toml:"tcp-nat-port-end"`
	UdpListenPort     uint16 `toml:"udp-listen-port"`
	UdpNatPortStart   uint16 `toml:"udp-nat-port-start"`
	UdpNatPortEnd     uint16 `toml:"udp-nat-port-end"`
}

type DNSConfig struct {
	ListenPort   uint16   `toml:"listen-port"`
	TTL          uint     `toml:"ttl"`
	PacketSize   uint16   `toml:"packet-size"`
	ReadTimeout  uint     `toml:"read-timeout"`
	WriteTimeout uint     `toml:"write-timeout"`
	Servers      []string `toml:"servers,omitempty"`
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
	Name string       `toml:"name"`
	Type OutboundType `toml:"type"`
	URL  string       `toml:"url,omitempty"`
}

func builtinOutbounds() [2]OutboundConfig {
	return [2]OutboundConfig{
		{Name: BuiltinDirect, Type: OutboundDirect},
		{Name: BuiltinReject, Type: OutboundReject},
	}
}

type RuleConfig struct {
	Schema   string `toml:"type"`
	Pattern  string `toml:"pattern,omitempty"`
	Outbound string `toml:"outbound"`
}

type KoneConfig struct {
	source    any
	General   GeneralConfig    `toml:"general"`
	Core      CoreConfig       `toml:"core"`
	DNS       DNSConfig        `toml:"dns"`
	Outbounds []OutboundConfig `toml:"outbounds"`
	Rule      []RuleConfig     `toml:"rules"`
}

func defaultConfig() *KoneConfig {
	return &KoneConfig{
		General: GeneralConfig{ManagerAddr: "127.0.0.1:9200", LogLevel: "info", LogFormat: "text"},
		Core: CoreConfig{Network: "10.192.0.1/16", Stack: "system", TcpListenPort: 82, TcpNatPortStart: 10000, TcpNatPortEnd: 60000,
			UdpListenPort: 82, UdpNatPortStart: 10000, UdpNatPortEnd: 60000},
		DNS: DNSConfig{ListenPort: DnsDefaultPort, TTL: DnsDefaultTtl, PacketSize: DnsDefaultPacketSize,
			ReadTimeout: DnsDefaultReadTimeout, WriteTimeout: DnsDefaultWriteTimeout},
	}
}

// ParseConfig reads a TOML filename or a copy of TOML bytes. Unknown keys are
// errors; a misspelled option never silently uses a default.
func ParseConfig(source any) (*KoneConfig, error) {
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
				cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{Name: key, Type: OutboundProxy, URL: value})
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
	for i := range cfg.Rule {
		cfg.Rule[i].Schema = strings.ToUpper(cfg.Rule[i].Schema)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func validateOutbounds(config []OutboundConfig) (map[string]OutboundType, error) {
	types := make(map[string]OutboundType, len(config)+2)
	for _, o := range builtinOutbounds() {
		types[o.Name] = o.Type
	}
	for i, o := range config {
		fail := func(reason string) error { return fmt.Errorf("outbounds[%d]: %s", i+1, reason) }
		if o.Name == "" || strings.TrimSpace(o.Name) != o.Name || strings.ContainsAny(o.Name, "\x00\r\n\t") {
			return nil, fail("name must be nonempty with no surrounding whitespace or control characters")
		}
		for _, builtin := range builtinOutbounds() {
			if strings.EqualFold(o.Name, builtin.Name) {
				return nil, fail("name is reserved for built-in outbound " + builtin.Name)
			}
		}
		if _, exists := types[o.Name]; exists {
			return nil, fail("duplicate outbound name " + o.Name)
		}
		switch o.Type {
		case OutboundProxy:
			if _, err := proxy.FromUrl(o.URL); err != nil {
				return nil, fail("invalid proxy URL (expected http, https or socks5 with host and port)")
			}
		case OutboundDirect, OutboundReject:
			return nil, fail("direct/reject are built-in; reference them in rules without an outbounds entry")
		default:
			return nil, fail("configured outbound type must be proxy; direct/reject are built-in")
		}
		types[o.Name] = o.Type
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
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("expected an IP address, optionally with a port")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", errors.New("DNS server must be an IP address")
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
	if strings.ContainsAny(cfg.Core.Tun, "\x00\r\n\t\"' ") {
		return errors.New("core.tun contains unsupported characters")
	}
	if cfg.Core.Stack != "system" && cfg.Core.Stack != "mixed" {
		return errors.New("core.stack must be system or mixed")
	}
	if cfg.Core.Stack == "mixed" && !singtun.WithGVisor {
		return errors.New("core.stack=mixed requires a build with -tags with_gvisor")
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
	if cfg.General.ManagerAddr != "" {
		host, port, err := net.SplitHostPort(cfg.General.ManagerAddr)
		if err != nil || validatePort(port) != nil || (host != "localhost" && host != "" && net.ParseIP(host) == nil) {
			return errors.New("general.manager-addr must be an IP address or localhost with a valid port")
		}
	}
	if _, err := logLevel(cfg.General.LogLevel); err != nil {
		return err
	}
	if cfg.General.LogFormat != "text" && cfg.General.LogFormat != "json" {
		return errors.New("general.log-format must be text or json")
	}
	for _, item := range []struct {
		name               string
		listen, start, end uint16
	}{
		{"tcp", cfg.Core.TcpListenPort, cfg.Core.TcpNatPortStart, cfg.Core.TcpNatPortEnd},
		{"udp", cfg.Core.UdpListenPort, cfg.Core.UdpNatPortStart, cfg.Core.UdpNatPortEnd},
	} {
		if item.listen == 0 {
			return fmt.Errorf("core.%s-listen-port must be nonzero", item.name)
		}
		if item.start == 0 || item.start >= item.end {
			return fmt.Errorf("core.%s-nat-port-start must be nonzero and less than the exclusive end", item.name)
		}
		if item.listen >= item.start && item.listen < item.end {
			return fmt.Errorf("core.%s-listen-port overlaps NAT port range", item.name)
		}
	}
	if cfg.DNS.ListenPort == 0 || cfg.DNS.ListenPort == cfg.Core.UdpListenPort {
		return errors.New("dns.listen-port must be nonzero and different from core.udp-listen-port")
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
	for i, server := range cfg.DNS.Servers {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return fmt.Errorf("dns.servers[%d]: %w", i+1, err)
		}
		host, _, _ := net.SplitHostPort(normalized)
		ip, _ := netip.ParseAddr(host)
		if ip.IsUnspecified() || ip.IsMulticast() || prefix.Contains(ip) {
			return fmt.Errorf("dns.servers[%d] is invalid or routed into the virtual network", i+1)
		}
	}
	types, err := validateOutbounds(cfg.Outbounds)
	if err != nil {
		return err
	}
	for i, r := range cfg.Rule {
		fail := func(reason string) error { return fmt.Errorf("rules[%d]: %s", i+1, reason) }
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
			return fail("IPv6 interception is not supported yet")
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
	level, err := logLevel(cfg.LogLevel)
	if err != nil {
		return err
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
		return errors.New("general.log-format must be text or json")
	}
	slog.SetDefault(slog.New(handler).With("service", "kone"))
	return nil
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

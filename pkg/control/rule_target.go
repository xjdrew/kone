package control

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type ruleTarget struct {
	Host    string `json:"host"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Keyword string `json:"keyword,omitempty"`
}

// Suggest from the bundled PSL, including private suffixes. Never resolve a name.
func suggestRuleTarget(target string) (ruleTarget, error) {
	fail := func() (ruleTarget, error) {
		return ruleTarget{}, errors.New("use a valid hostname or IP address, optionally with a port")
	}
	host := strings.TrimSpace(target)
	if host == "" || len(host) > 1024 {
		return fail()
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if _, err := netip.ParseAddr(host); err != nil && strings.Contains(host, ":") {
		name, port, err := net.SplitHostPort(host)
		if err != nil {
			return fail()
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return fail()
		}
		host = name
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap().WithZone("")
		typeName, bits := "IP-CIDR6", "/128"
		if address.Is4() {
			typeName, bits = "IP-CIDR", "/32"
		}
		return ruleTarget{Host: address.String(), Type: typeName, Pattern: address.String() + bits}, nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) == 0 || len(host) > 253 {
		return fail()
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fail()
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
				return fail()
			}
		}
	}
	result := ruleTarget{Host: host, Type: "DOMAIN-SUFFIX", Pattern: host, Keyword: labels[0]}
	// Unknown/internal suffixes retain the complete host rather than guessing a boundary.
	suffix, icann := publicsuffix.PublicSuffix(host)
	if !icann && !strings.Contains(suffix, ".") {
		// Some TLDs (e.g. *.ck) exist only as wildcard rules in the PSL.
		if _, known := publicsuffix.PublicSuffix("kone." + labels[len(labels)-1]); !known {
			return result, nil
		}
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// A public suffix alone has no registrable domain. Start with an exact match.
		result.Type = "DOMAIN"
		return result, nil
	}
	result.Pattern = root
	result.Keyword, _, _ = strings.Cut(root, ".")
	return result, nil
}

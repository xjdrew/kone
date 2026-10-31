package dnsconfig

import (
	"net"
	"testing"
)

func TestReadSystemDNS(t *testing.T) {
	cfg := ReadDnsConfig()
	if cfg == nil || cfg.Err != nil {
		t.Fatalf("read DNS: %+v", cfg)
	}
	if len(cfg.Servers) == 0 || cfg.Timeout <= 0 || cfg.Attempts <= 0 {
		t.Fatalf("incomplete DNS configuration: %+v", cfg)
	}
	for _, server := range cfg.Servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil || net.ParseIP(host) == nil || port != "53" {
			t.Fatalf("invalid DNS server %q", server)
		}
	}
}

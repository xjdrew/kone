package kone

// DNSDefaults describes discovered upstreams, not a connectivity measurement.
// Public fallback is explicit so interfaces cannot label it as OS discovery.
type DNSDefaults struct {
	Servers        []string `json:"servers"`
	Source         string   `json:"source"`
	PublicFallback bool     `json:"public_fallback"`
	Warnings       []string `json:"warnings"`
}

func InspectDNSDefaults(cfg DNSConfig) DNSDefaults {
	cfg.Servers = nil
	if cfg.Mode == "" {
		cfg.Mode = "host"
	}
	effective, err := effectiveDNSConfig(cfg, systemDNSServers)
	if err != nil {
		return DNSDefaults{PublicDNSDefaults(), "public_fallback", true, []string{"system_dns_discovery_failed"}}
	}
	observed, observationErr := readDNSSystemContext()
	effective = mergeSystemDNSContext(effective, observed, observationErr)
	return DNSDefaults{effective.Servers, effective.SystemContext.Source, effective.SystemContext.PublicFallback, effective.SystemContext.Warnings}
}

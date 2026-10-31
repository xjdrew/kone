package kone

import "testing"

func FuzzParseConfig(f *testing.F) {
	cleanProxyEnv(f)
	for _, input := range []string{"", "[core]\nnetwork='10.192.0.1/16'", "[[outbounds]]\nname='office'\nurl='http://127.0.0.1:8080'\nudp-fallback='direct'", "[[rules]]\ntype='FINAL'\noutbound='reject'", "[core]\ntcp-listen-port=82"} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65536 {
			t.Skip()
		}
		cfg, err := ParseConfig(input)
		if err == nil {
			if err := cfg.Validate(); err != nil {
				t.Fatalf("accepted invalid configuration: %v", err)
			}
			if _, err := NewOutbounds(cfg.Outbounds); err != nil {
				t.Fatalf("accepted invalid outbounds: %v", err)
			}
		}
	})
}

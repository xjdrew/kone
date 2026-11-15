package desktop

import "github.com/xjdrew/kone/pkg/kone"

func NeedsHelperForConfig(cfg *kone.KoneConfig) bool {
	return NeedsHelper() || kone.SystemDNSNeedsAuthorization(cfg.DNS) || cfg.DNS.PersistentFakeIP && kone.FakeIPNeedsAuthorization()
}

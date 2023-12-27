//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

type Rule struct {
	directDomains map[string]bool // always direct connect for proxy domain
	patterns      []Pattern
}

func (rule *Rule) DirectDomain(domain string) {
	logger.Debugf("[rule] add direct domain: %s", domain)
	rule.directDomains[domain] = true
}

// match a proxy for target `val`
func (rule *Rule) Proxy(val interface{}) string {
	if domain, ok := val.(string); ok {
		if rule.directDomains[domain] {
			logger.Debugf("[rule match] %v, proxy %q", val, "DIRECT")
			return "DIRECT" // direct
		}
	}

	for _, pattern := range rule.patterns {
		if pattern.Match(val) {
			proxy := pattern.Proxy()
			logger.Debugf("[rule match] %v, proxy %s", val, proxy)
			return proxy
		}
	}
	logger.Debugf("[rule final] %v, proxy %q", val, "")
	return "DIRECT" // direct connect
}

func NewRule(rcs []RuleConfig) *Rule {
	rule := &Rule{
		directDomains: map[string]bool{},
	}

	for _, rc := range rcs {
		if pattern := CreatePattern(rc); pattern != nil {
			rule.patterns = append(rule.patterns, pattern)
		}
	}
	return rule
}

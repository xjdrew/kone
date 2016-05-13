package k1

type Rule struct {
	patterns []Pattern
	final    string
}

func (rule *Rule) DirectDomain(domain string) {
	logger.Debugf("[rule] add direct domain: %s", domain)
	pattern := rule.patterns[0].(*DomainSuffixPattern)
	pattern.AddDomain(domain)
}

// match a proxy for target `val`
func (rule *Rule) Proxy(val interface{}) (bool, string) {
	for _, pattern := range rule.patterns {
		if pattern.Match(val) {
			proxy := pattern.Proxy()
			logger.Debugf("[rule] %v -> %s: proxy %q", val, pattern.Name(), proxy)
			return true, proxy
		}
	}
	logger.Debugf("[rule] %v -> final: proxy %q", val, rule.final)
	return false, rule.final
}

func NewRule(config RuleConfig, patterns map[string]*PatternConfig) *Rule {
	rule := new(Rule)
	rule.final = config.Final
	pattern := NewDomainSuffixPattern("__internal__", "", nil)
	rule.patterns = append(rule.patterns, pattern)
	for _, name := range config.Pattern {
		if patternConfig, ok := patterns[name]; ok {
			if pattern := CreatePattern(name, patternConfig); pattern != nil {
				rule.patterns = append(rule.patterns, pattern)
			}
		}
	}
	return rule
}

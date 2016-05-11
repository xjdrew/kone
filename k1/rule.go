package k1

type Rule struct {
	patterns []Pattern
	final    string
}

func (rule *Rule) Proxy(val interface{}) string {
	for _, pattern := range rule.patterns {
		if pattern.Match(val) {
			proxy := pattern.Proxy()
			logger.Debugf("[rule] %v -> %s: proxy %q", val, pattern.Name(), proxy)
			return proxy
		}
	}
	logger.Debugf("[rule] %v -> final: proxy %q", val, rule.final)
	return rule.final
}

func NewRule(config RuleConfig, patterns map[string]*PatternConfig) *Rule {
	rule := new(Rule)
	rule.final = config.Final
	for _, name := range config.Pattern {
		if patternConfig, ok := patterns[name]; ok {
			if pattern := CreatePattern(name, patternConfig); pattern != nil {
				rule.patterns = append(rule.patterns, pattern)
			}
		}
	}
	return rule
}

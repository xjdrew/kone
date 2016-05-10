package k1

type Rule struct {
	patterns []Pattern
	final    string
}

func (rule *Rule) Proxy(val interface{}) string {
	for _, pattern := range rule.patterns {
		if pattern.Match(val) {
			return pattern.Proxy()
		}
	}
	return rule.final
}

func NewRule(config RuleConfig, patterns map[string]*PatternConfig) *Rule {
	rule := new(Rule)
	rule.final = config.Final
	for _, name := range config.Pattern {
		if patternConfig, ok := patterns[name]; ok {
			if pattern := CreatePattern(patternConfig); pattern != nil {
				rule.patterns = append(rule.patterns, pattern)
			}
		}
	}
	return rule
}

package k1

type Rule struct {
	patterns []Pattern
	final    string
}

func (ps *Rule) Proxy(val interface{}) string {
	return ""
}

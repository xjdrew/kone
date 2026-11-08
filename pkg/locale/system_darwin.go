package locale

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func SystemLanguage() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if data, err := exec.CommandContext(ctx, "/usr/bin/defaults", "read", "-g", "AppleLanguages").Output(); err == nil {
		values := strings.FieldsFunc(string(data), func(r rune) bool { return r == '(' || r == ')' || r == ',' || r == '"' || r == '\n' || r == ' ' })
		return Match(values...)
	}
	return Match(environmentLanguage())
}

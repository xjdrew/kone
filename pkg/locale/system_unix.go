//go:build !windows && !darwin

package locale

func SystemLanguage() string { return Match(environmentLanguage()) }

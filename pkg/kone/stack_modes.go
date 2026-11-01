package kone

const (
	StackSystem = "system"
	StackGVisor = "gvisor"
	StackMixed  = "mixed"
)

// SupportedStacks reports runtime choices in every KONE build. The upstream
// dependency's with_gvisor tag is supplied by all supported build/test tasks.
func SupportedStacks() []string { return []string{StackSystem, StackGVisor, StackMixed} }

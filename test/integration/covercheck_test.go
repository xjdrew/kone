package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverageGateCLI(t *testing.T) {
	_, binary := buildBinary(t, "./cmd/covercheck")
	for _, tc := range []struct {
		name, base, head, want string
		exit                   int
	}{
		{"equal", "a.go:1.1,2.2 2 1\na.go:3.1,4.2 2 0", "a.go:1.1,2.2 1 1\na.go:3.1,4.2 1 0", "PASS", 0},
		{"increase", "a.go:1.1,2.2 1 0", "a.go:1.1,2.2 1 1", "PASS", 0},
		{"untested file lowers coverage", "a.go:1.1,2.2 1 1", "a.go:1.1,2.2 1 1\nb.go:1.1,2.2 1 0", "coverage decreased", 1},
		{"duplicate blocks do not inflate coverage", "a.go:1.1,2.2 1 1", "a.go:1.1,2.2 1 1\na.go:1.1,2.2 1 1\nb.go:1.1,2.2 1 0", "coverage decreased", 1},
		{"malformed base", "invalid", "a.go:1.1,2.2 1 1", "base coverage", 2},
		{"empty head", "a.go:1.1,2.2 1 1", "", "head coverage", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base, head := filepath.Join(dir, "base profile.out"), filepath.Join(dir, "head profile.out")
			for path, data := range map[string]string{base: tc.base, head: tc.head} {
				if err := os.WriteFile(path, []byte("mode: atomic\n"+data+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(binary, "-base", base, "-head", head)
			out, err := cmd.CombinedOutput()
			exit := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					exit = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if exit != tc.exit || !strings.Contains(string(out), tc.want) {
				t.Fatalf("exit=%d want=%d output=%s", exit, tc.exit, out)
			}
		})
	}
}

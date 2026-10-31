// Package integration verifies the public CLI without requiring TUN privileges.
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildBinary(t *testing.T, pkg string) (string, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("builds CLI")
	}
	root := filepath.Join("..", "..")
	binary := filepath.Join(t.TempDir(), filepath.Base(pkg))
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, pkg)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return root, binary
}

func TestCLI(t *testing.T) {
	root, binary := buildBinary(t, "./cmd/kone")
	for _, tc := range []struct {
		name string
		args []string
		want string
		exit int
	}{
		{"version", []string{"-version"}, "Version:", 0},
		{"help", []string{"-help"}, "TOML", 0},
		{"check", []string{"-check", "-config", "configs/kone.example.toml"}, "Configuration valid", 0},
		{"positional", []string{"-check", "configs/kone.example.toml"}, "Configuration valid", 0},
		{"missing", []string{"-check", "-config", "does-not-exist.toml"}, "Configuration error", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, tc.args...)
			cmd.Dir = root
			// Tests must be independent of developer/runner proxy configuration.
			for _, env := range os.Environ() {
				key, _, _ := strings.Cut(env, "=")
				switch strings.ToLower(key) {
				case "http_proxy", "https_proxy", "socks_proxy":
					continue
				}
				cmd.Env = append(cmd.Env, env)
			}
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
				t.Fatalf("exit=%d, want=%d; output=%s", exit, tc.exit, out)
			}
		})
	}
}

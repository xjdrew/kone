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
	root, binary := buildBinary(t, "./cmd/kone-cli")
	configs := t.TempDir()
	for name, content := range map[string]string{
		"builtins": `
[[rules]]
type = "DOMAIN-SUFFIX"
pattern = "blocked.example"
outbound = "reject"
[[rules]]
type = "FINAL"
outbound = "direct"
`,
		"override": "[[outbounds]]\nname='DIRECT'\nurl='http://127.0.0.1:8080'",
		"alias":    "[[outbounds]]\nname='local'\ntype='direct'",
		"proxy":    "[core]\nstack='system'\n[[outbounds]]\nname='office'\nurl='socks5://127.0.0.1:1080'\n[[rules]]\ntype='FINAL'\noutbound='office'",
		"stack":    "[core]\nstack='unknown'",
		"udp":      "[[outbounds]]\nname='office'\nurl='http://127.0.0.1:8080'\nudp-fallback='direct'",
		"bad-udp":  "[[outbounds]]\nname='office'\nurl='http://127.0.0.1:8080'\nudp-fallback='office'",
		"legacy":   "[core]\nudp-nat-port-start=10000",
	} {
		if err := os.WriteFile(filepath.Join(configs, name+".toml"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
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
		{"builtins without outbounds", []string{"-check", "-config", filepath.Join(configs, "builtins.toml")}, "Configuration valid", 0},
		{"builtin override", []string{"-check", "-config", filepath.Join(configs, "override.toml")}, "reserved for built-in outbound direct", 2},
		{"builtin alias", []string{"-check", "-config", filepath.Join(configs, "alias.toml")}, "unknown configuration key", 2},
		{"proxy and explicit stack", []string{"-check", "-config", filepath.Join(configs, "proxy.toml")}, "Configuration valid", 0},
		{"invalid stack", []string{"-check", "-config", filepath.Join(configs, "stack.toml")}, "core.stack must be system or mixed", 2},
		{"explicit UDP fallback", []string{"-check", "-config", filepath.Join(configs, "udp.toml")}, "Configuration valid", 0},
		{"invalid UDP fallback", []string{"-check", "-config", filepath.Join(configs, "bad-udp.toml")}, "udp-fallback must be direct or reject", 2},
		{"removed relay setting", []string{"-check", "-config", filepath.Join(configs, "legacy.toml")}, "unknown configuration key", 2},
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

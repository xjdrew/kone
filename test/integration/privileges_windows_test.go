package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCLIWindowsPrivileges(t *testing.T) {
	root, binary := buildBinary(t, "./cmd/kone")
	config := filepath.Join(t.TempDir(), "config with spaces.toml")
	if err := os.WriteFile(config, []byte("[dns]\nservers=['1.1.1.1']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(invalid, []byte("[core]\nunknown-setting=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		args           []string
		want           string
		exit           int
		unelevatedOnly bool
	}{
		{"version without config", []string{"-version", "-config", config + ".missing"}, "Version:", 0, false},
		{"help", []string{"-help"}, "TOML", 0, false},
		{"check", []string{"-check", "-config", config}, "Configuration valid", 0, false},
		{"check with elevation disabled", []string{"-no-elevate", "-check", "-config", config}, "Configuration valid", 0, false},
		{"invalid config", []string{"-no-elevate", "-config", invalid}, "unknown configuration key", 2, false},
		{"missing config", []string{"-no-elevate", "-config", config + ".missing"}, "Configuration error", 2, false},
		{"unelevated startup", []string{"-no-elevate", "-config", config}, "PowerShell or Windows Terminal as Administrator", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unelevatedOnly && windows.GetCurrentProcessToken().IsElevated() {
				t.Skip("refusal regression requires an unelevated process")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, tc.args...)
			cmd.Dir = root
			for _, env := range os.Environ() {
				key, _, _ := strings.Cut(env, "=")
				switch strings.ToLower(key) {
				case "http_proxy", "https_proxy", "socks_proxy":
					continue
				}
				cmd.Env = append(cmd.Env, env)
			}
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("CLI did not finish before timeout: %v\n%s", ctx.Err(), out)
			}
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

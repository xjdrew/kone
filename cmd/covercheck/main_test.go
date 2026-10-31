package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCoverage(t *testing.T) {
	// Includes an untested file, a duplicate hit, CRLF and a Windows path.
	profile := "mode: atomic\r\np/a.go:1.1,2.2 3 0\r\np/a.go:1.1,2.2 3 7\r\np/a.go:1.1,2.2 3 0\r\nC:/source with spaces/b.go:1.1,2.2 7 0\r\n"
	got, err := readCoverage(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	if got != (coverage{covered: 3, total: 10}) {
		t.Fatalf("got %+v, want 3/10", got)
	}
	for _, mode := range []string{"set", "count", "atomic"} {
		if _, err := readCoverage(strings.NewReader("mode: " + mode + "\np/a.go:1.1,2.2 1 1\n")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadCoverageRejectsInvalidProfiles(t *testing.T) {
	cases := []string{
		"", "mode: unknown\n", "mode: count\n", "mode: count\na.go:1.1,2.2 0 0\n",
		"mode: count\nmalformed\n", "mode: count\na.go:1.1,2.2 1 -1\n",
		"mode: count\na.go:1.1,2.2 1 0\na.go:1.1,2.2 2 1\n",
		"mode: count\na.go:1.1,2.2 18446744073709551616 0\n",
		"mode: count\na.go:1.1,2.2 1 18446744073709551616\n",
		"mode: count\na.go:1.1,2.2 18446744073709551615 1\nb.go:1.1,2.2 1 0\n",
		"mode: count\n" + strings.Repeat("x", 70000),
	}
	for i, profile := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := readCoverage(strings.NewReader(profile)); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}

func writeProfile(t *testing.T, c coverage) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "coverage with spaces.out")
	profile := fmt.Sprintf("mode: atomic\na.go:1.1,2.2 %d 1\na.go:3.1,4.2 %d 0\n", c.covered, c.total-c.covered)
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCoverageGate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		base, head coverage
		exit       int
	}{
		{"equal", coverage{1, 2}, coverage{5, 10}, 0},
		{"increase", coverage{1, 2}, coverage{6, 10}, 0},
		{"decrease", coverage{1, 2}, coverage{4, 10}, 1},
		{"untested new code", coverage{50, 100}, coverage{50, 101}, 1},
		{"same rounded percentage", coverage{1, 3}, coverage{333333332, 1000000000}, 1},
		{"large exact fractions", coverage{math.MaxUint64 - 1, math.MaxUint64}, coverage{math.MaxUint64 - 2, math.MaxUint64 - 1}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, err bytes.Buffer
			exit := run([]string{"-base", writeProfile(t, tc.base), "-head", writeProfile(t, tc.head)}, &out, &err)
			if exit != tc.exit {
				t.Fatalf("exit=%d want=%d; stdout=%s stderr=%s", exit, tc.exit, &out, &err)
			}
			if tc.exit == 1 && !strings.Contains(err.String(), "coverage decreased") {
				t.Fatalf("unexpected failure: %s", &err)
			}
		})
	}
}

func TestUsageAndMissingProfiles(t *testing.T) {
	valid := writeProfile(t, coverage{1, 2})
	bad := filepath.Join(t.TempDir(), "bad.out")
	if err := os.WriteFile(bad, []byte("not a profile"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		exit int
	}{
		{nil, 2}, {[]string{"-help"}, 0}, {[]string{"-unknown"}, 2},
		{[]string{"-base", valid, "-head", valid, "extra"}, 2},
		{[]string{"-base", bad, "-head", valid}, 2},
		{[]string{"-base", valid, "-head", bad}, 2},
		{[]string{"-base", valid, "-head", bad + ".missing"}, 2},
	} {
		var out, err bytes.Buffer
		if got := run(tc.args, &out, &err); got != tc.exit {
			t.Errorf("args=%v exit=%d want=%d: %s", tc.args, got, tc.exit, &err)
		}
	}
}

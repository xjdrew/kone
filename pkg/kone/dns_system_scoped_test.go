package kone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testScopedDNSID = "12345678-1234-1234-1234-123456789abc"

func scopedProfileText(profile scopedDNSProfile) []byte {
	if profile == nil {
		return []byte("  No such key\n")
	}
	var out strings.Builder
	out.WriteString("<dictionary> {\n")
	keys := make([]string, 0, len(profile))
	for key := range profile {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := profile[key]
		if key == "ServerAddresses" || key == "SupplementalMatchDomains" || key == "SupplementalMatchOrders" {
			fmt.Fprintf(&out, " %s : <array> {\n", key)
			for index, value := range values {
				fmt.Fprintf(&out, " %d : %s\n", index, value)
			}
			out.WriteString(" }\n")
		} else {
			fmt.Fprintf(&out, " %s : %s\n", key, values[0])
		}
	}
	out.WriteString("}\n")
	return []byte(out.String())
}

type scopedInput struct{ close func() error }

func (s scopedInput) Write(data []byte) (int, error) { return len(data), nil }
func (s scopedInput) Close() error                   { return s.close() }

type scopedFixture struct {
	mu                                                             sync.Mutex
	profile, expected                                              scopedDNSProfile
	wait                                                           chan error
	processOnce                                                    sync.Once
	readCount, launchCount, closeCount, killCount                  int
	readErrorAt                                                    int
	launchError, publish, wrong, external, ignoreEOF, exitAtLaunch bool
	cleanupReadError                                               bool
	script                                                         string
}

func newScopedFixture(t *testing.T) *scopedFixture {
	t.Helper()
	_, _, profile, err := scopedDNSScript(testScopedDNSID, "utun17", netip.MustParseAddr("198.18.1.1"), 20553)
	require.NoError(t, err)
	return &scopedFixture{expected: profile, wait: make(chan error, 1), publish: true}
}

func (f *scopedFixture) end(err error) {
	f.processOnce.Do(func() {
		f.mu.Lock()
		if !f.external {
			f.profile = nil
		}
		f.mu.Unlock()
		f.wait <- err
	})
}

func (f *scopedFixture) hooks() scopedDNSHooks {
	return scopedDNSHooks{
		read: func(ctx context.Context, key string) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			f.readCount++
			if f.readCount == f.readErrorAt || f.cleanupReadError && f.closeCount > 0 {
				return nil, errors.New("injected store read failure")
			}
			return scopedProfileText(f.profile), nil
		},
		launch: func(script string) (scopedDNSProcess, error) {
			f.mu.Lock()
			f.launchCount++
			f.script = script
			if f.launchError {
				f.mu.Unlock()
				return scopedDNSProcess{}, errors.New("injected session launch failure")
			}
			if f.publish {
				f.profile = scopedDNSProfile{}
				for key, values := range f.expected {
					f.profile[key] = append([]string(nil), values...)
				}
				if f.wrong {
					f.profile["ServerPort"] = []string{"1"}
				}
			}
			f.mu.Unlock()
			if f.exitAtLaunch {
				f.end(io.EOF)
			}
			return scopedDNSProcess{
				input: scopedInput{close: func() error {
					f.mu.Lock()
					f.closeCount++
					ignore := f.ignoreEOF
					f.mu.Unlock()
					if !ignore {
						f.end(nil)
					}
					return nil
				}},
				wait: func() error { return <-f.wait },
				kill: func() error { f.mu.Lock(); f.killCount++; f.mu.Unlock(); f.end(errors.New("killed")); return nil },
			}, nil
		},
	}
}

func (f *scopedFixture) configure(ctx context.Context, verify func() error) (Cleanup, <-chan error, error) {
	return configureScopedDNS(ctx, f.hooks(), testScopedDNSID, "utun17", netip.MustParseAddr("198.18.1.1"), 20553, verify)
}

func TestScopedDNSLeaseOwnsOnlyOneTemporaryKeyAndConcurrentCleanup(t *testing.T) {
	f := newScopedFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cleanup, failures, err := f.configure(ctx, func() error { return nil })
	require.NoError(t, err)
	require.Contains(t, f.script, "add State:/Network/Service/"+testScopedDNSID+"/DNS temporary")
	require.Contains(t, f.script, "d.add SupplementalMatchOrders * # 1\n")
	require.NotContains(t, f.script, "d.add SearchOrder")
	require.NotContains(t, f.script, "set ")
	require.NotContains(t, f.script, "Global/")
	require.NotContains(t, f.script, "remove ")
	var workers sync.WaitGroup
	errorsCh := make(chan error, 8)
	for range 8 {
		workers.Go(func() { errorsCh <- cleanup(t.Context()) })
	}
	workers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		require.NoError(t, err)
	}
	f.mu.Lock()
	require.Nil(t, f.profile)
	require.Equal(t, 1, f.closeCount)
	require.Zero(t, f.killCount)
	f.mu.Unlock()
	_, open := <-failures
	require.False(t, open)
}

func TestScopedDNSStartupFaultsReturnOwnedRollback(t *testing.T) {
	for _, fault := range []string{"existing", "read-before", "launch", "read-after", "wrong", "timeout", "device-before", "device-after", "exit"} {
		t.Run(fault, func(t *testing.T) {
			f := newScopedFixture(t)
			budget := 2 * time.Second
			if fault == "timeout" {
				budget = 15 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), budget)
			defer cancel()
			verifyCalls := 0
			verify := func() error {
				verifyCalls++
				if fault == "device-before" || fault == "device-after" && verifyCalls > 1 {
					return errors.New("owned device changed")
				}
				return nil
			}
			switch fault {
			case "existing":
				f.profile = f.expected
			case "read-before":
				f.readErrorAt = 1
			case "launch":
				f.launchError = true
			case "read-after":
				f.readErrorAt = 2
			case "wrong":
				f.wrong = true
			case "timeout":
				f.publish = false
			case "exit":
				f.exitAtLaunch = true
			}
			cleanup, _, err := f.configure(ctx, verify)
			require.Error(t, err)
			if cleanup != nil {
				require.NoError(t, cleanup(t.Context()))
			}
			if fault == "existing" {
				require.Equal(t, f.expected, f.profile)
			} else {
				require.Nil(t, f.profile)
			}
		})
	}
}

func TestScopedDNSUnexpectedSessionDeathAndExternalReplacement(t *testing.T) {
	for _, scenario := range []string{"death", "replacement", "read-failure", "device-reused"} {
		t.Run(scenario, func(t *testing.T) {
			f := newScopedFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			var changed sync.Mutex
			deviceChanged := false
			cleanup, failures, err := f.configure(ctx, func() error {
				changed.Lock()
				defer changed.Unlock()
				if deviceChanged {
					return errors.New("reused device")
				}
				return nil
			})
			require.NoError(t, err)
			switch scenario {
			case "death":
				f.end(io.EOF)
			case "replacement":
				f.mu.Lock()
				f.external = true
				f.profile["ServerAddresses"] = []string{"192.0.2.9"}
				f.mu.Unlock()
			case "read-failure":
				f.mu.Lock()
				f.readErrorAt = f.readCount + 1
				f.mu.Unlock()
			case "device-reused":
				changed.Lock()
				deviceChanged = true
				changed.Unlock()
			}
			select {
			case err, open := <-failures:
				require.True(t, open)
				require.Error(t, err)
			case <-ctx.Done():
				t.Fatal("lost lease was not reported")
			}
			err = cleanup(t.Context())
			if scenario == "replacement" {
				require.ErrorContains(t, err, "external settings preserved")
				require.Equal(t, []string{"192.0.2.9"}, f.profile["ServerAddresses"])
			} else {
				require.NoError(t, err)
				require.Nil(t, f.profile)
			}
		})
	}
}

func TestScopedDNSHealthyLeaseAndUnverifiableReplacement(t *testing.T) {
	f := newScopedFixture(t)
	cleanup, failures, err := f.configure(t.Context(), func() error { return nil })
	require.NoError(t, err)
	require.Eventually(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.readCount >= 3 }, 2*time.Second, 20*time.Millisecond)
	select {
	case <-failures:
		t.Fatal("a healthy lease must remain valid")
	default:
	}
	// A different session can copy the exact public dictionary. Ownership lives
	// in configd, not in the dictionary, so absence must still be confirmed.
	f.mu.Lock()
	f.external = true
	f.mu.Unlock()
	budget, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	require.Error(t, cleanup(budget))
	f.mu.Lock()
	require.Equal(t, f.expected, f.profile)
	f.mu.Unlock()
}

func TestScopedDNSCleanupReadErrorIsReported(t *testing.T) {
	f := newScopedFixture(t)
	cleanup, _, err := f.configure(t.Context(), func() error { return nil })
	require.NoError(t, err)
	f.mu.Lock()
	f.cleanupReadError = true
	f.mu.Unlock()
	require.ErrorContains(t, cleanup(t.Context()), "injected store read failure")
}

func TestScopedDNSUnresponsiveSessionIsKilledOnlyByItsOwnHandle(t *testing.T) {
	f := newScopedFixture(t)
	f.ignoreEOF = true
	cleanup, _, err := f.configure(t.Context(), func() error { return nil })
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	require.Error(t, cleanup(ctx)) // removal cannot be verified after the budget.
	f.mu.Lock()
	require.Equal(t, 1, f.killCount)
	require.Nil(t, f.profile)
	f.mu.Unlock()
}

func TestScopedDNSInputAndMachineOutputBoundaries(t *testing.T) {
	for _, id := range []string{"", "../key", testScopedDNSID + "\nremove key"} {
		_, _, _, err := scopedDNSScript(id, "utun1", netip.MustParseAddr("198.18.1.1"), 53)
		require.Error(t, err)
	}
	for _, iface := range []string{"en0", "utun1\nquit", "utun999999999"} {
		_, _, _, err := scopedDNSScript(testScopedDNSID, iface, netip.MustParseAddr("198.18.1.1"), 53)
		require.Error(t, err)
	}
	_, _, _, err := scopedDNSScript(testScopedDNSID, "utun1", netip.MustParseAddr("::1"), 53)
	require.Error(t, err)
	_, _, _, err = scopedDNSScript(testScopedDNSID, "utun1", netip.MustParseAddr("198.18.1.1"), 0)
	require.Error(t, err)
	for _, data := range []string{"", "not a dictionary", "<dictionary> {\n}\nextra", "<dictionary> {\nx\n}", "<dictionary> {\nx : 1\nx : 2\n}", "<dictionary> {\nx : <array> {\n2 : wrong\n}\n}", "<dictionary> {\nx : <array> {", strings.Repeat("x", 65537)} {
		_, _, err := parseScopedDNSProfile([]byte(data))
		require.Error(t, err)
	}
	_, _, err = parseScopedDNSProfile([]byte("<dictionary> {\nx : " + strings.Repeat("y", 5000) + "\n}"))
	require.Error(t, err)
	var excessive strings.Builder
	excessive.WriteString("<dictionary> {\n")
	for index := range 17 {
		fmt.Fprintf(&excessive, "key%d : value\n", index)
	}
	excessive.WriteString("}\n")
	_, _, err = parseScopedDNSProfile([]byte(excessive.String()))
	require.Error(t, err)
	excessive.Reset()
	excessive.WriteString("<dictionary> {\nx : <array> {\n")
	for index := range 17 {
		fmt.Fprintf(&excessive, "%d : value\n", index)
	}
	excessive.WriteString("}\n}\n")
	_, _, err = parseScopedDNSProfile([]byte(excessive.String()))
	require.Error(t, err)
	f := newScopedFixture(t)
	profile, exists, err := parseScopedDNSProfile(scopedProfileText(f.expected))
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, f.expected, profile)
}

package process

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func procFixture(t *testing.T) (string, Query) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"net", "self", "42/fd"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0700))
	}
	now := time.Now()
	query := testQuery(now)
	encode := func(endpoint netip.AddrPort) string {
		data := endpoint.Addr().As4()
		return fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(data[:]), endpoint.Port())
	}
	line := fmt.Sprintf("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: %s %s 01 00000000:00000000 00:00000000 00000000 1000 0 12345\n", encode(query.Source), encode(query.Destination))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(line), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "stat"), []byte(fmt.Sprintf("btime %d\n", now.Unix()-100)), 0600))
	word := int(unsafe.Sizeof(uintptr(0)))
	aux := make([]byte, 4*word)
	if word == 8 {
		binary.NativeEndian.PutUint64(aux, 17)
		binary.NativeEndian.PutUint64(aux[word:], 100)
	} else {
		binary.NativeEndian.PutUint32(aux, 17)
		binary.NativeEndian.PutUint32(aux[word:], 100)
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "self", "auxv"), aux, 0600))
	stat := "42 (browser with ) parentheses) R " + strings.Repeat("0 ", 18) + "1000 0 0\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "42", "stat"), []byte(stat), 0600))
	require.NoError(t, os.Symlink("socket:[12345]", filepath.Join(root, "42", "fd", "3")))
	require.NoError(t, os.Symlink("/usr/bin/browser", filepath.Join(root, "42", "exe")))
	return root, query
}

func TestProcSocketInodeAndPIDStarttimeValidation(t *testing.T) {
	root, query := procFixture(t)
	result, err := lookupProc(context.Background(), root, query)
	require.NoError(t, err)
	require.Equal(t, uint32(42), result.PID)
	require.Equal(t, "browser", result.Name)
	require.Equal(t, "linux_proc_inode_starttime", result.Source)
	require.True(t, result.StartedAt.Before(query.ObservedAt))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "43", "fd"), 0700))
	require.NoError(t, os.Symlink("socket:[12345]", filepath.Join(root, "43", "fd", "4")))
	_, err = lookupProc(context.Background(), root, query)
	require.ErrorContains(t, err, "shared")
	require.NoError(t, os.Remove(filepath.Join(root, "43", "fd", "4")))
	require.NoError(t, os.Remove(filepath.Join(root, "42", "exe")))
	_, err = lookupProc(context.Background(), root, query)
	require.Error(t, err, "unreadable executable metadata stays unknown")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = lookupProc(ctx, root, query)
	require.ErrorIs(t, err, context.Canceled)
}

func TestProcParsingRejectsAmbiguityAndMalformedIdentity(t *testing.T) {
	for _, raw := range []string{"bad", "GGGGGGGG:0010", "0100007F:zzzz"} {
		_, err := procEndpoint(raw)
		require.Error(t, err)
	}
	for _, raw := range []string{"missing-parentheses", "1 (x) R 0", "1 (x) R " + strings.Repeat("0 ", 18) + "bad"} {
		_, err := procStart([]byte(raw))
		require.Error(t, err)
	}
	root, query := procFixture(t)
	data, err := os.ReadFile(filepath.Join(root, "net", "tcp"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "tcp"), append(data, []byte(strings.ReplaceAll(strings.Split(string(data), "\n")[1], "12345", "54321"))...), 0600))
	_, err = procSocket(context.Background(), root, query)
	require.ErrorContains(t, err, "ambiguous")
	_, err = boundedDir(filepath.Join(root, "net"), 0)
	require.Error(t, err)
}

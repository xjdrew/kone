package integration

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/application"
)

type quietStartupOutput struct{ ready chan string }

func (output quietStartupOutput) Write(data []byte) (int, error) {
	if index := strings.Index(string(data), "http://"); index >= 0 {
		select {
		case output.ready <- strings.TrimSpace(string(data[index:])):
		default:
		}
	}
	return len(data), nil
}

func TestQuietManagementStartupServesFirstSetupWithoutCaptureOrNativeUI(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	// Use the public console entry with both UI surfaces disabled, including
	// its failure paths. The desktop entry's injected UI matrix is package-tested.
	directory := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan int, 1)
	output := quietStartupOutput{ready: make(chan string, 1)}
	go func() {
		result <- application.Run(ctx, []string{"-data-dir", directory, "-listen", "127.0.0.1:0", "-no-browser", "-no-tray"}, output, io.Discard, "desktop-startup-test")
	}()
	var access string
	select {
	case access = <-output.ready:
	case code := <-result:
		t.Fatalf("quiet management stopped before becoming ready (exit %d)", code)
	case <-time.After(5 * time.Second):
		t.Fatal("quiet management did not become ready")
	}
	parsed, err := url.Parse(access)
	require.NoError(t, err)
	parsed.Fragment = ""
	base := parsed.String()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	require.Eventually(t, func() bool {
		response, err := client.Get(base + "api/v1/auth")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		var auth struct {
			SetupRequired bool `json:"setup_required"`
			Authenticated bool `json:"authenticated"`
		}
		return response.StatusCode == http.StatusOK && json.NewDecoder(response.Body).Decode(&auth) == nil && auth.SetupRequired && !auth.Authenticated
	}, 5*time.Second, 25*time.Millisecond)
	response, err := client.Get(base)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	cancel()
	select {
	case code := <-result:
		require.Zero(t, code)
	case <-time.After(3 * time.Second):
		t.Fatal("quiet desktop startup did not stop")
	}
	_, err = os.Stat(filepath.Join(directory, "settings.json"))
	require.NoError(t, err)
	for _, name := range []string{"capture.json", "auth.json"} {
		_, err = os.Stat(filepath.Join(directory, name))
		require.True(t, os.IsNotExist(err), "viewing first setup cannot start capture or create a management password")
	}
}

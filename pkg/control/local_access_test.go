package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfiguredNativeAndStartupLinksRequirePasswordWithoutSendingBootstrap(t *testing.T) {
	c := testController(t, Options{})
	original := c.BootstrapToken()
	owner(t, c)
	c.mu.Lock()
	c.address = "127.0.0.1:9200"
	c.mu.Unlock()
	access, err := c.LocalAccessURL()
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:9200/", access)
	require.Empty(t, c.BootstrapToken())
	require.Equal(t, 401, request(t, c, "", "GET", "/api/v1/state", nil).Code)
	require.Equal(t, 401, request(t, c, "", "POST", "/api/v1/session", map[string]any{"token": original}).Code)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready, done := make(chan string, 1), make(chan error, 1)
	go func() { done <- c.Serve(ctx, "127.0.0.1:0", func(value string) { ready <- value }) }()
	select {
	case url := <-ready:
		require.NotContains(t, url, "#")
		require.NotContains(t, url, "token")
		require.True(t, strings.HasPrefix(url, "http://127.0.0.1:"))
	case <-time.After(3 * time.Second):
		t.Fatal("configured management did not become ready")
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("management did not stop")
	}
}

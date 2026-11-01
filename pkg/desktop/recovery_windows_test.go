package desktop

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowsDNSRecoveryRejectsInvalidOrCanceledRequestsBeforeAuthorization(t *testing.T) {
	launch := func(context.Context, string, []string) error {
		t.Fatal("invalid or canceled recovery must not request UAC")
		return nil
	}
	require.Error(t, RecoverSystemDNS(t.Context(), strings.Repeat("a", 32), nil))
	require.Error(t, RecoverSystemDNS(t.Context(), "invalid", launch))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, RecoverSystemDNS(ctx, strings.Repeat("a", 32), launch), context.Canceled)
}

package application

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSRecoveryRequestsAuthorizationOnlyWhenNeeded(t *testing.T) {
	for _, needs := range []bool{false, true} {
		t.Run(map[bool]string{false: "already_admin", true: "needs_helper"}[needs], func(t *testing.T) {
			direct, helper := 0, 0
			denied := errors.New("test recovery error")
			err := selectSystemDNSRecovery(t.Context(), "lease-id", func() bool { return needs }, func(context.Context, string) error { direct++; return denied }, func(context.Context, string) error { helper++; return denied })
			require.ErrorIs(t, err, denied)
			if needs {
				require.Equal(t, 0, direct)
				require.Equal(t, 1, helper)
			} else {
				require.Equal(t, 1, direct)
				require.Equal(t, 0, helper)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			require.ErrorIs(t, selectSystemDNSRecovery(ctx, "lease-id", func() bool { t.Fatal("canceled recovery must not inspect privileges"); return false }, nil, nil), context.Canceled)
		})
	}
}

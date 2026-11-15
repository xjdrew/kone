package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestLinuxCanceledAuthorizationPreservesProfileAndManagement(t *testing.T) {
	c, err := control.New(control.Options{Directory: t.TempDir(),
		InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) { return nil, nil },
		Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport {
			return kone.PreflightReport{Ready: true, Issues: []kone.PreflightIssue{{Code: "privileges", Severity: "info", Message: "Authorize on enable"}}}
		},
		Factory: func(cfg *kone.KoneConfig) (control.Engine, error) {
			return desktop.NewEngine(cfg, func(context.Context, string, []string) error {
				return &desktop.AuthorizationError{Code: "authorization_canceled", Cause: errors.New("native dialog dismissed")}
			})
		},
	})
	require.NoError(t, err)
	defer c.Close()
	before := c.Document()
	require.True(t, c.Readiness(t.Context()).Ready)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	err = c.Start(ctx)
	var coded interface{ ErrorCode() string }
	require.ErrorAs(t, err, &coded)
	require.Equal(t, "authorization_canceled", coded.ErrorCode())
	require.NoError(t, ctx.Err())
	require.Equal(t, "paused", c.State().DataState)
	require.Equal(t, before, c.Document())
	require.True(t, c.Readiness(t.Context()).Ready)
}

package desktop

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

type failingStartupEngine struct{ *kone.One }

func (*failingStartupEngine) Run(context.Context) error {
	return &kone.CaptureSetupError{Code: "system_dns", Cause: errors.New("resolver http://user:private-password@127.0.0.1 is unavailable")}
}

func TestHelperStartupPreservesTranslatedErrorCodeAndRedactsDetails(t *testing.T) {
	for _, factoryFailure := range []bool{true, false} {
		t.Run(map[bool]string{true: "factory", false: "run"}[factoryFailure], func(t *testing.T) {
			cfg := kone.DefaultConfig()
			cfg.DNS.Servers = []string{"127.0.0.1:5353"}
			parent, child := net.Pipe()
			events, childEvents := net.Pipe()
			helperDone := make(chan error, 1)
			go func() {
				helperDone <- ServeHelper(t.Context(), child, childEvents, func(cfg *kone.KoneConfig) (NetworkEngine, error) {
					if factoryFailure {
						return nil, (&failingStartupEngine{}).Run(t.Context())
					}
					one, err := kone.FromConfig(cfg)
					return &failingStartupEngine{one}, err
				})
			}()
			remote, err := NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) { return parent, events, nil })
			require.NoError(t, err)
			t.Cleanup(func() { remote.Close(); parent.Close(); events.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err = remote.Run(ctx)
			var coded interface{ ErrorCode() string }
			require.ErrorAs(t, err, &coded)
			require.Equal(t, "system_dns", coded.ErrorCode())
			require.NotContains(t, err.Error(), "private-password")
			select {
			case <-remote.Ready():
				t.Fatal("failed startup was reported ready")
			default:
			}
			remote.Close()
			select {
			case <-helperDone:
			case <-ctx.Done():
				t.Fatal("helper did not stop")
			}
		})
	}
}

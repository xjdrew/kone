//go:build !windows

package desktop

import (
	"context"
	"errors"

	"github.com/xjdrew/kone/pkg/kone"
)

type LaunchHelper func(context.Context, string, []string) error

func PrivilegeSeparationAvailable() bool { return false }
func NeedsHelper() bool                  { return false }
func NewEngine(*kone.KoneConfig, LaunchHelper) (*RemoteEngine, error) {
	return nil, errors.New("privilege-separated desktop helper is currently implemented on Windows only")
}
func Preflight(ctx context.Context, cfg *kone.KoneConfig) kone.PreflightReport {
	return kone.Preflight(ctx, cfg)
}
func RunNetworkHelper(context.Context, string, uint32) error {
	return errors.New("private network helper is unavailable on this platform")
}

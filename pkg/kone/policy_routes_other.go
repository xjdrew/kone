//go:build !linux && !darwin && !windows

package kone

import "errors"

func systemPolicyRoutes() ([]policyRoute, error) {
	return nil, errors.New("native policy route inspection is unavailable on this platform")
}

package desktop

import (
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"testing"
)

func TestConnectionHealthReadAndStaleActionCrossHelperIPC(t *testing.T) {
	remote, _, finished := helperHarness(t, false)
	done := startRemote(t, remote)
	state, err := remote.HealthData(kone.HealthQuery{Offset: 0, Limit: 10, Status: "attention"})
	require.NoError(t, err)
	require.Empty(t, state.Entries)
	require.False(t, state.AutoEnabled)
	_, err = remote.HealthAction(kone.HealthAction{Action: "apply", Domain: "x.com", Generation: 1, Version: 7})
	require.Error(t, err)
	require.NoError(t, remote.Close())
	require.NoError(t, <-done)
	require.NoError(t, <-finished)
}

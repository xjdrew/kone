package desktop

import (
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"testing"
)

func TestRemoteSmartBelongsToHelperAndDoesNotStartAnotherWorker(t *testing.T) {
	remote, _, finished := helperHarness(t, false)
	done := startRemote(t, remote)
	state, err := remote.SmartData()
	require.NoError(t, err)
	require.False(t, state.Enabled)
	require.Empty(t, state.Suggestions)
	_, err = remote.SmartAction(kone.SmartAction{Action: "clear"})
	require.NoError(t, err)
	_, err = remote.SmartAction(kone.SmartAction{Action: "preview", ID: "missing"})
	require.Error(t, err)
	require.NoError(t, remote.Close())
	require.NoError(t, <-done)
	require.NoError(t, <-finished)
}

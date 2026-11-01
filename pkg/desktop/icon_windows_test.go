package desktop

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowsTrayLoadsBrandedIconWithoutExecutableResources(t *testing.T) {
	icon, err := loadTrayIcon(0)
	require.NoError(t, err)
	require.NotZero(t, icon)
	result, _, _ := trayUser32.NewProc("DestroyIcon").Call(icon)
	require.NotZero(t, result, "owned notification icon must be releasable")
}

package application

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalManagementPageURLKeepsOneUseTokenInFragment(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:12345/#token=one-use-secret", "http://[::1]:12345/#token=one-use-secret", "http://127.0.0.1:12345/#token=one%2Buse%26secret"} {
		for _, page := range []string{"home", "diagnostics"} {
			target, err := localManagementPageURL(raw, page)
			require.NoError(t, err)
			parsed, err := url.Parse(target)
			require.NoError(t, err)
			require.Empty(t, parsed.RawQuery)
			require.NotContains(t, strings.Split(target, "#")[0], "token")
			fragment, err := url.ParseQuery(parsed.EscapedFragment())
			require.NoError(t, err)
			require.Equal(t, page, fragment.Get("page"))
			original, err := url.Parse(raw)
			require.NoError(t, err)
			originalFragment, err := url.ParseQuery(original.EscapedFragment())
			require.NoError(t, err)
			require.Equal(t, originalFragment.Get("token"), fragment.Get("token"))
			require.Equal(t, original.Host, parsed.Host)
		}
	}
}

func TestLocalManagementPageURLRejectsUnsafeDestinationsWithoutEchoingCredentials(t *testing.T) {
	for _, raw := range []string{"http://example.com/#token=one-use-secret", "http://127.0.0.1/?token=one-use-secret", "http://user:one-use-secret@127.0.0.1/#token=one-use-secret", "file:///tmp/#token=one-use-secret", "http://127.0.0.1/path/#token=one-use-secret", "http://127.0.0.1/#token=one-use-secret&token=other", "http://127.0.0.1/#token=%invalid", "http://127.0.0.1/#page=diagnostics"} {
		_, err := localManagementPageURL(raw, "diagnostics")
		require.Error(t, err)
		require.NotContains(t, err.Error(), "one-use-secret")
	}
	_, err := localManagementPageURL("http://127.0.0.1/#token=one-use-secret", "https://example.com")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "one-use-secret")
}

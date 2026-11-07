package locale

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLanguageFallbackAndCatalogParity(t *testing.T) {
	for _, test := range []struct {
		candidates []string
		want       string
	}{{[]string{"zh_CN.UTF-8"}, "zh"}, {[]string{"fr-CA", "zh-Hant"}, "zh"}, {[]string{"en-GB"}, "en"}, {[]string{"C.UTF-8"}, "en"}, {nil, "en"}} {
		require.Equal(t, test.want, Match(test.candidates...))
	}
	english := load()["en"].Messages
	for language, catalog := range load() {
		require.Len(t, catalog.Messages, len(english), language)
		for key := range english {
			require.NotEmpty(t, catalog.Messages[key], language+":"+key)
		}
	}
	require.Equal(t, "Enable proxy", Text("fr", "proxy.enable"))
	require.NotEqual(t, "Enable proxy", Text("zh", "proxy.enable"))
	require.Equal(t, "unknown.key", Text("zh", "unknown.key"))
}

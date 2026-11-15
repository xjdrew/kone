package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"golang.org/x/net/html"
)

func TestUnauthenticatedManagementHTMLStartsWithAnIsolatedShell(t *testing.T) {
	// Inspect the actual embedded document before JavaScript or styles load.
	// A slow or failed bootstrap must leave management controls both hidden
	// and outside keyboard/assistive-technology interaction from first paint.
	c, err := control.New(control.Options{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := server.Client()
	response, err := client.Get(server.URL + "/")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, response.Header.Get("Content-Type"), "text/html")
	document, err := html.Parse(response.Body)
	require.NoError(t, err)

	attribute := func(node *html.Node, name string) (string, bool) {
		for _, item := range node.Attr {
			if item.Key == name {
				return item.Val, true
			}
		}
		return "", false
	}
	var walk func(*html.Node)
	roots, modules := 0, 0
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			id, _ := attribute(node, "id")
			if id == "root" {
				roots++
				require.Nil(t, node.FirstChild, "no private content may be embedded before authentication")
			}
			switch node.Data {
			case "button", "input", "nav", "dialog", "table":
				t.Errorf("management element %s rendered before authentication", node.Data)
			case "script":
				kind, _ := attribute(node, "type")
				source, _ := attribute(node, "src")
				require.Equal(t, "module", kind)
				require.True(t, len(source) > 8 && source[:8] == "/assets/", "offline module must be served by the management host")
				modules++
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	require.Equal(t, 1, roots)
	require.Equal(t, 1, modules)

	// Public HTML availability does not grant access to management data.
	response, err = client.Get(server.URL + "/api/v1/state")
	require.NoError(t, err)
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
}

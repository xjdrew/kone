package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	protected := map[string]bool{}
	var main *html.Node
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			id, _ := attribute(node, "id")
			class, _ := attribute(node, "class")
			label := ""
			switch {
			case id == "main":
				main = node
			case id == "navigation", id == "lifecycle-toggle", id == "sidebar", id == "toast-region":
				label = id
			case node.Data == "footer":
				label = "footer"
			case strings.Contains(" "+class+" ", " skip-link "):
				label = "skip-link"
			}
			if label != "" {
				protected[label] = true
				isolated := false
				for parent := node; parent != nil; parent = parent.Parent {
					if _, marked := attribute(parent, "data-management-shell"); !marked {
						continue
					}
					_, hidden := attribute(parent, "hidden")
					_, inert := attribute(parent, "inert")
					isolated = hidden && inert
					break
				}
				require.True(t, isolated, "%s must start inside a hidden, inert management boundary", label)
			}
			if node.Data == "dialog" {
				_, open := attribute(node, "open")
				require.False(t, open, "management dialogs must not be open before authentication")
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	require.Len(t, protected, 6, "exercise every management surface in the embedded HTML")
	require.NotNil(t, main, "the authentication/loading surface must remain available")
	for node := main; node != nil; node = node.Parent {
		_, hidden := attribute(node, "hidden")
		_, inert := attribute(node, "inert")
		require.False(t, hidden, "initial loading must remain visible")
		require.False(t, inert, "the authentication surface must remain interactive")
	}

	// Public HTML availability does not grant access to management data.
	response, err = client.Get(server.URL + "/api/v1/state")
	require.NoError(t, err)
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
}

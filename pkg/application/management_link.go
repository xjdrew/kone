package application

import (
	"errors"
	"net/netip"
	"net/url"
)

// Native shortcuts carry one-use credentials in the fragment only. Keep their
// destination vocabulary separate from actions: opening diagnostics never runs
// a probe and cannot redirect the browser to an arbitrary page or host.
func localManagementPageURL(raw, page string) (string, error) {
	if page != "home" && page != "diagnostics" {
		return "", errors.New("unsupported local management page")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Opaque != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("invalid local management URL")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.IsLoopback() {
		return "", errors.New("local management URL must use loopback")
	}
	fragment, err := url.ParseQuery(parsed.EscapedFragment())
	token := fragment.Get("token")
	if err != nil || len(fragment["token"]) != 1 || token == "" || len(token) > 512 {
		return "", errors.New("invalid local management bootstrap fragment")
	}
	parsed.Fragment, parsed.RawFragment = "", ""
	return parsed.String() + "#token=" + url.QueryEscape(token) + "&page=" + page, nil
}

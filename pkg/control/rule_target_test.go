package control

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuleTargetSuggestionsRespectPublicAndPrivateBoundaries(t *testing.T) {
	c := testController(t, Options{})
	owner(t, c)
	token, _ := roleSession(c, "read")
	require.Equal(t, 401, request(t, c, "", "GET", "/api/v1/rules/target?target=x.com", nil).Code)
	for _, tc := range []struct{ target, host, kind, pattern, keyword string }{
		{"www.google.com", "www.google.com", "DOMAIN-SUFFIX", "google.com", "google"},
		{"news.china.gov.cn", "news.china.gov.cn", "DOMAIN-SUFFIX", "china.gov.cn", "china"},
		{"x.com", "x.com", "DOMAIN-SUFFIX", "x.com", "x"},
		{"  WWW.Google.COM.:443  ", "www.google.com", "DOMAIN-SUFFIX", "google.com", "google"},
		{"a.b.example.co.uk", "a.b.example.co.uk", "DOMAIN-SUFFIX", "example.co.uk", "example"},
		{"www.example.com.au", "www.example.com.au", "DOMAIN-SUFFIX", "example.com.au", "example"},
		{"a.school.k12.ca.us", "a.school.k12.ca.us", "DOMAIN-SUFFIX", "school.k12.ca.us", "school"},
		{"www.alice.github.io", "www.alice.github.io", "DOMAIN-SUFFIX", "alice.github.io", "alice"},
		{"a.project.appspot.com", "a.project.appspot.com", "DOMAIN-SUFFIX", "project.appspot.com", "project"},
		{"www.city.kawasaki.jp", "www.city.kawasaki.jp", "DOMAIN-SUFFIX", "city.kawasaki.jp", "city"},
		{"a.b.ck", "a.b.ck", "DOMAIN-SUFFIX", "a.b.ck", "a"},
		{"a.www.ck", "a.www.ck", "DOMAIN-SUFFIX", "www.ck", "www"},
		{"www.xn--85x722f.com.cn", "www.xn--85x722f.com.cn", "DOMAIN-SUFFIX", "xn--85x722f.com.cn", "xn--85x722f"},
		{"a.team.internal", "a.team.internal", "DOMAIN-SUFFIX", "a.team.internal", "a"},
		{"service.corp.test", "service.corp.test", "DOMAIN-SUFFIX", "service.corp.test", "service"},
		{"localhost", "localhost", "DOMAIN-SUFFIX", "localhost", "localhost"},
		{"co.uk", "co.uk", "DOMAIN", "co.uk", "co"},
		{"com", "com", "DOMAIN", "com", "com"},
		{"ck", "ck", "DOMAIN", "ck", "ck"},
		{"api_service.internal", "api_service.internal", "DOMAIN-SUFFIX", "api_service.internal", "api_service"},
		{"github.io", "github.io", "DOMAIN", "github.io", "github"},
		{"149.154.167.50:443", "149.154.167.50", "IP-CIDR", "149.154.167.50/32", ""},
		{"192.168.1.1", "192.168.1.1", "IP-CIDR", "192.168.1.1/32", ""},
		{"[2001:0db8::1]:443", "2001:db8::1", "IP-CIDR6", "2001:db8::1/128", ""},
		{"[::1]", "::1", "IP-CIDR6", "::1/128", ""},
		{"2001:db8::2", "2001:db8::2", "IP-CIDR6", "2001:db8::2/128", ""},
		{"::ffff:192.0.2.1", "192.0.2.1", "IP-CIDR", "192.0.2.1/32", ""},
		{"[fe80::1%eth0]:80", "fe80::1", "IP-CIDR6", "fe80::1/128", ""},
	} {
		t.Run(tc.target, func(t *testing.T) {
			response := request(t, c, token, "GET", "/api/v1/rules/target?target="+url.QueryEscape(tc.target), nil)
			require.Equal(t, 200, response.Code, response.Body.String())
			var target ruleTarget
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &target))
			require.Equal(t, ruleTarget{Host: tc.host, Type: tc.kind, Pattern: tc.pattern, Keyword: tc.keyword}, target)
		})
	}
	for _, target := range []string{"", "https://google.com", "a..com", "a.com:0", "a.com:65536", "a.com:no", "[::1", "::1]", "a/b.com", "a b.com", "a.com?x", "user@a.com", "*.google.com", ".com", "-bad.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 128) + "com", strings.Repeat("a", 1025)} {
		response := request(t, c, token, "GET", "/api/v1/rules/target?target="+url.QueryEscape(target), nil)
		require.Equal(t, 400, response.Code, target+": "+response.Body.String())
	}
	require.Equal(t, "paused", c.State().DataState)
}

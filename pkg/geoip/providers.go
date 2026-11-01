package geoip

import "slices"

// Provider describes a supported data schema and its publisher's terms. It is
// not a claim that an uploaded database was actually issued by that publisher.
type Provider struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Source          string   `json:"source"`
	License         string   `json:"license"`
	LicenseURL      string   `json:"license_url"`
	Attribution     string   `json:"attribution"`
	AttributionURL  string   `json:"attribution_url"`
	UpdateFrequency string   `json:"update_frequency"`
	AccountRequired bool     `json:"account_required"`
	Formats         []string `json:"formats"`
}

var providers = []Provider{
	{ID: "dbip-lite", Name: "DB-IP Country Lite", Source: "https://db-ip.com/db/download/ip-to-country-lite", License: "CC-BY-4.0", LicenseURL: "https://creativecommons.org/licenses/by/4.0/", Attribution: "IP Geolocation by DB-IP", AttributionURL: "https://db-ip.com", UpdateFrequency: "monthly", Formats: []string{"mmdb"}},
	{ID: "ipinfo-lite", Name: "IPinfo Lite", Source: "https://ipinfo.io/lite", License: "CC-BY-SA-4.0", LicenseURL: "https://creativecommons.org/licenses/by-sa/4.0/", Attribution: "IP address data powered by IPinfo", AttributionURL: "https://ipinfo.io", UpdateFrequency: "daily", AccountRequired: true, Formats: []string{"mmdb"}},
	{ID: "maxmind-geolite2", Name: "MaxMind GeoLite2 Country", Source: "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/", License: "CC-BY-SA-4.0 and GeoLite End User License Agreement", LicenseURL: "https://www.maxmind.com/en/geolite/eula", Attribution: "This product includes GeoLite2 data created by MaxMind", AttributionURL: "https://www.maxmind.com", UpdateFrequency: "Tuesday and Friday", AccountRequired: true, Formats: []string{"mmdb"}},
}

func Providers() []Provider {
	result := slices.Clone(providers)
	for i := range result {
		result[i].Formats = slices.Clone(result[i].Formats)
	}
	return result
}

func FindProvider(id string) (Provider, bool) {
	for _, provider := range Providers() {
		if provider.ID == id {
			return provider, true
		}
	}
	return Provider{}, false
}

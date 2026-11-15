// Package locale contains the shared offline UI and desktop message catalog.
package locale

import (
	"embed"
	"encoding/json"
	"os"
	"strings"
	"sync"
)

//go:embed catalog/*.json
var catalogs embed.FS

type Catalog struct {
	Metadata struct {
		Tag       string `json:"tag"`
		Name      string `json:"name"`
		Direction string `json:"dir"`
	} `json:"metadata"`
	Messages map[string]string `json:"messages"`
}

var load = sync.OnceValue(func() map[string]Catalog {
	result := map[string]Catalog{}
	files, _ := catalogs.ReadDir("catalog")
	for _, file := range files {
		data, _ := catalogs.ReadFile("catalog/" + file.Name())
		var catalog Catalog
		if json.Unmarshal(data, &catalog) == nil && catalog.Metadata.Tag != "" {
			result[strings.ToLower(catalog.Metadata.Tag)] = catalog
		}
	}
	return result
})

func Match(candidates ...string) string {
	for _, value := range candidates {
		value = strings.ToLower(strings.ReplaceAll(strings.Split(strings.Split(value, ".")[0], "@")[0], "_", "-"))
		for value != "" {
			if _, exists := load()[value]; exists {
				return value
			}
			index := strings.LastIndex(value, "-")
			if index < 0 {
				break
			}
			value = value[:index]
		}
	}
	return "en"
}

func environmentLanguage() string {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return "en"
}

func Text(language, key string) string {
	if value := load()[Match(language)].Messages[key]; value != "" {
		return value
	}
	if value := load()["en"].Messages[key]; value != "" {
		return value
	}
	return key
}

var desktopLanguage = sync.OnceValue(SystemLanguage)

func Desktop(key string) string { return Text(desktopLanguage(), key) }

// HostLanguage is captured once per process; polling the management state must
// not invoke native preference tools on the data collection path.
func HostLanguage() string { return desktopLanguage() }

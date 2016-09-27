package k1

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"
)

const masterTmpl = `
{{define "header"}}
<!DOCTYPE HTML>
<html>
<head>
<title>{{.Title}}</title>
<meta charset='utf-8'>
<style>
/**
 * Styles for TABLE that uses a thin collapsed border.
 */
table {
  border-collapse: collapse;
}

table, table th, table td {
  border: 1px solid #777;
  padding-left: 4px;
  padding-right: 4px;
}

table th {
  background: rgb(224,236,255);
}

table th.title {
  background: rgb(255,217,217);
}
</style>
</head>
<body>
{{end}}

{{define "footer"}}
</body>
</html>
{{end}}

{{define "index"}}
{{template "header" .}}
<h2>List of URLs</h2>
<ul>
{{range .URLs}}
<li><a href='{{.}}'>{{.}}</a></li>
{{end}}
</ul>
{{template "footer" .}}
{{end}}

{{define "host_data"}}
{{template "header" .}}
<h3>{{.Title}}</h3>
<table>
<tr>
<th>Name</th>
<th>Upload</th>
<th>Download</th>
<th>Last</th>
</tr>
{{range .Records}}
<tr>
<td>{{.Name}}</td>
<td>{{.Upload}}</td>
<td>{{.Download}}</td>
<td>{{.Touch.Format "2006-01-02 15:04:05.000"}}</td>
</tr>
{{end}}
</table>
{{template "footer" .}}
{{end}}

{{define "dns"}}
{{template "header" .}}
<h3>Current State</h3>
<ul>
<li>Active entries: {{.ActiveEntries}}</li>
<li>Expired entries:{{.ExpiredEntries}}</li>
</ul>
<table>
<tr>
<th>Hostname</th>
<th>Address</th>
<th>Proxy</th>
<th>Hits</th>
<th>Expires</th>
</tr>
{{range .Records}}
<tr>
<td>{{.Hostname}}</td>
<td>{{.IP}}</td>
<td>{{.Proxy}}</td>
<td>{{.Hits}}</td>
<td>{{.Expires.Format "2006-01-02 15:04:05.000"}}{{if .Expires.Before $.Now}}[expired]{{end}}</td>
</tr>
{{end}}
</table>
{{template "footer" .}}
{{end}}
`

// statistical data of every connection
type ConnData struct {
	Src      string
	Dst      string
	Proxy    string
	Upload   int64
	Download int64
}

// statistical data of every host
type HostData struct {
	Name     string
	Upload   int64
	Download int64
	Touch    time.Time
}

type Manager struct {
	one    *One
	listen string
	tmpl   *template.Template

	dataCh       chan ConnData
	hosts        map[string]*HostData
	destinations map[string]*HostData
	proxies      map[string]*HostData
}

func handleWrapper(f func(io.Writer, *http.Request) error) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		w := bytes.NewBuffer(nil)
		err := f(w, r)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Internal server error: %s", err), http.StatusInternalServerError)
		} else {
			rw.Write(w.Bytes())
		}
	}
}

func (m *Manager) indexHandle(w io.Writer, r *http.Request) error {
	return m.tmpl.ExecuteTemplate(w, "index", map[string]interface{}{
		"Title": "kone",
		"URLs": []string{
			"/host",
			"/destination",
			"/proxy",
			"/dns",
		},
	})
}

func (m *Manager) hostHandle(w io.Writer, r *http.Request) error {
	return m.tmpl.ExecuteTemplate(w, "host_data", map[string]interface{}{
		"Title":   "Host Data",
		"Records": m.hosts,
	})
}

func (m *Manager) destinationHandle(w io.Writer, r *http.Request) error {
	return m.tmpl.ExecuteTemplate(w, "host_data", map[string]interface{}{
		"Title":   "Destination Data",
		"Records": m.destinations,
	})
}

func (m *Manager) proxyHandle(w io.Writer, r *http.Request) error {
	return m.tmpl.ExecuteTemplate(w, "host_data", map[string]interface{}{
		"Title":   "Proxy Data",
		"Records": m.proxies,
	})
}

func (m *Manager) dnsHandle(w io.Writer, r *http.Request) error {
	records := m.one.dnsTable.records

	activeEntries, expiredEntires := 0, 0
	now := time.Now()
	for _, record := range records {
		if record.Expires.Before(now) {
			expiredEntires += 1
		} else {
			activeEntries += 1
		}
	}

	return m.tmpl.ExecuteTemplate(w, "dns", map[string]interface{}{
		"Title":          "dns cache",
		"ActiveEntries":  activeEntries,
		"ExpiredEntries": expiredEntires,
		"Now":            now,
		"Records":        records,
	})
}

// statistical data api
func (m *Manager) consumeData() {
	accumulate := func(s map[string]*HostData, name string, upload int64, download int64, now time.Time) {
		if o, ok := s[name]; ok {
			o.Upload += upload
			o.Download += download
			o.Touch = now
		} else {
			s[name] = &HostData{
				Name:     name,
				Upload:   upload,
				Download: download,
				Touch:    now,
			}
		}
	}

	for data := range m.dataCh {
		now := time.Now()
		accumulate(m.hosts, data.Src, data.Upload, data.Download, now)
		accumulate(m.destinations, data.Dst, data.Upload, data.Download, now)
		accumulate(m.proxies, data.Proxy, data.Upload, data.Download, now)
	}
}

func (m *Manager) Serve() error {
	http.HandleFunc("/", handleWrapper(m.indexHandle))
	http.HandleFunc("/host", handleWrapper(m.hostHandle))
	http.HandleFunc("/destination", handleWrapper(m.destinationHandle))
	http.HandleFunc("/proxy", handleWrapper(m.proxyHandle))
	http.HandleFunc("/dns", handleWrapper(m.dnsHandle))
	logger.Infof("[manager] listen on: %s", m.listen)
	go m.consumeData()
	return http.ListenAndServe(m.listen, nil)
}

func NewManager(one *One, cfg ManagerConfig) *Manager {
	if cfg.Listen == "" {
		return nil
	}
	return &Manager{
		one:          one,
		listen:       cfg.Listen,
		dataCh:       make(chan ConnData),
		hosts:        make(map[string]*HostData),
		destinations: make(map[string]*HostData),
		proxies:      make(map[string]*HostData),
		tmpl:         template.Must(template.New("master").Parse(masterTmpl)),
	}
}

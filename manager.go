package kone

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
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
a {
    color: #428BCA;
    text-decoration: none;
}

a:hover, a:focus {
    color: #2A6496;
    text-decoration: underline;
}
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

table td {
  text-align: right;
}

table th {
  background: rgb(224,236,255);
  text-align: left;
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
<hr>
<h2>Current State</h2>
<table>
<tr><th>Total Hosts</th><td>{{.TotalHosts}}</td></tr>
<tr><th>Total Websites</th><td>{{.TotalWebistes}}</td></tr>
<tr><th>Total Proxies</th><td>{{.TotalProxies}}</td></tr>
<tr><th>Total Traffic</th><td>{{formatNumberComma .TotalTraffic}}</td></tr>
<tr><th>Upload Traffic</th><td>{{formatNumberComma .UploadTraffic}}</td></tr>
<tr><th>Download Traffic</th><td>{{formatNumberComma .DownloadTraffic}}</td></tr>
<tr><th>Uptime</th><td>{{.Uptime}}</td></tr>
<tr><th>Now</th><td>{{.Now.Format "2006-01-02 15:04:05.000"}}</td></tr>
</table>
{{template "footer" .}}
{{end}}

{{define "traffic_record"}}
{{template "header" .}}
<h2>{{.Title}}</h2>
<ul>
<li>Entries: {{len .Records}}</li>
<li>Total: {{sumInt64 .Upload .Download | formatNumberComma}}</li>
<li>Upload: {{formatNumberComma .Upload}}</li>
<li>Download: {{formatNumberComma .Download}}</li>
</ul>
<table>
<tr>
<th>Name</th>
<th>Total</th>
<th>Upload</th>
<th>Download</th>
<th>Last</th>
</tr>
{{range .Records}}
<tr>
<td>
{{if $.HasDetail}}
	<a href="{{.Name}}">{{.Name}}</a>
{{else}}
	{{.Name}}
{{end}}
</td>
<td>{{sumInt64 .Upload .Download | formatNumberComma}}</td>
<td>{{formatNumberComma .Upload}}</td>
<td>{{formatNumberComma .Download}}</td>
<td>{{.Touch.Format "2006-01-02 15:04:05.000"}}</td>
</tr>
{{end}}
</table>
{{template "footer" .}}
{{end}}

{{define "traffic_record_detail"}}
{{template "header" .}}
{{with .Record}}
<h2>{{$.Title}}: {{.Name}}</h2>
<ul>
<li>Entries: {{len .Details}}</li>
<li>Total: {{sumInt64 .Upload .Download | formatNumberComma}}</li>
<li>Upload: {{formatNumberComma .Upload}}</li>
<li>Download: {{formatNumberComma .Download}}</li>
<li>Last: {{.Touch.Format "2006-01-02 15:04:05.000"}}</li>
</ul>
{{end}}
{{with .Record.Details}}
<table>
<tr>
<th>Name</th>
<th>Total</th>
<th>Upload</th>
<th>Download</th>
<th>Last</th>
</tr>
{{range .}}
<tr>
<td>{{.EndPoint}}</td>
<td>{{sumInt64 .Upload .Download | formatNumberComma}}</td>
<td>{{formatNumberComma .Upload}}</td>
<td>{{formatNumberComma .Download}}</td>
<td>{{.Touch.Format "2006-01-02 15:04:05.000"}}</td>
</tr>
{{end}}
</table>
{{end}}
{{template "footer" .}}
{{end}}

{{define "dns"}}
{{template "header" .}}
<h2>Current State</h2>
<ul>
<li>Dns server: {{.DnsServer}}</li>
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
<td>{{.Expires.Format "2006-01-02 15:04:05.000"}}{{if .Expires.Before $.Now}}<span style="color:red">[expired]</span>{{end}}</td>
</tr>
{{end}}
</table>
{{template "footer" .}}
{{end}}


{{define "config"}}
{{template "header" .}}
<h2>Config</h2>
<ul>
<li>rules: {{.RuleCount}}</li>
</ul>
<table>
<tr>
<th>Source</th>
</tr>
<tr>
<td style="text-align:left;"><pre>{{.Source}}</pre></td>
</tr>
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

// statistical data of every host/website/proxy
type TrafficRecordDetail struct {
	EndPoint string
	Upload   int64
	Download int64
	Touch    time.Time
}

type TrafficRecord struct {
	Name     string
	Upload   int64
	Download int64
	Touch    time.Time
	Details  map[string]*TrafficRecordDetail
}

type Manager struct {
	one       *One
	cfg       *KoneConfig
	startTime time.Time // process start time
	listen    string
	tmpl      *template.Template

	dataCh   chan ConnData
	hosts    map[string]*TrafficRecord
	websites map[string]*TrafficRecord
	proxies  map[string]*TrafficRecord
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
	var upload, download int64
	for _, v := range m.proxies {
		upload += v.Upload
		download += v.Download
	}
	return m.tmpl.ExecuteTemplate(w, "index", map[string]interface{}{
		"Title":           "kone",
		"Now":             time.Now(),
		"Uptime":          time.Since(m.startTime),
		"TotalHosts":      len(m.hosts),
		"TotalWebistes":   len(m.websites),
		"TotalProxies":    len(m.proxies),
		"TotalTraffic":    upload + download,
		"UploadTraffic":   upload,
		"DownloadTraffic": download,
		"URLs": []string{
			"/host/",
			"/website/",
			"/proxy/",
			"/dns/",
			"/reload/",
			"/config/",
		},
	})
}

func (m *Manager) hostHandle(w io.Writer, r *http.Request) error {
	name := strings.TrimPrefix(r.RequestURI, "/host/")
	record, ok := m.hosts[name]
	if ok {
		return m.tmpl.ExecuteTemplate(w, "traffic_record_detail", map[string]interface{}{
			"Title":  "Host Record Detail",
			"Record": record,
		})
	} else {
		var upload, download int64
		for _, v := range m.hosts {
			upload += v.Upload
			download += v.Download
		}
		return m.tmpl.ExecuteTemplate(w, "traffic_record", map[string]interface{}{
			"Title":     "Host Record",
			"Upload":    upload,
			"Download":  download,
			"Records":   m.hosts,
			"HasDetail": true,
		})
	}
}

func (m *Manager) websiteHandle(w io.Writer, r *http.Request) error {
	name := strings.TrimPrefix(r.RequestURI, "/website/")
	record, ok := m.websites[name]
	if ok {
		return m.tmpl.ExecuteTemplate(w, "traffic_record_detail", map[string]interface{}{
			"Title":  "Website Record Detail",
			"Record": record,
		})
	} else {
		var upload, download int64
		for _, v := range m.websites {
			upload += v.Upload
			download += v.Download
		}
		return m.tmpl.ExecuteTemplate(w, "traffic_record", map[string]interface{}{
			"Title":     "Website Record",
			"Upload":    upload,
			"Download":  download,
			"Records":   m.websites,
			"HasDetail": true,
		})
	}
}

func (m *Manager) proxyHandle(w io.Writer, r *http.Request) error {
	var upload, download int64
	for _, v := range m.proxies {
		upload += v.Upload
		download += v.Download
	}
	return m.tmpl.ExecuteTemplate(w, "traffic_record", map[string]interface{}{
		"Title":    "Proxy Data",
		"Upload":   upload,
		"Download": download,
		"Records":  m.proxies,
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
		"DnsServer":      strings.Join(m.one.dns.nameservers, ","),
		"ActiveEntries":  activeEntries,
		"ExpiredEntries": expiredEntires,
		"Now":            now,
		"Records":        records,
	})
}

func (m *Manager) reloadHandle(w io.Writer, r *http.Request) error {
	logger.Infof("[manager] reload config")
	newcfg, err := ParseConfig(m.cfg.source)
	if err != nil {
		return err
	}

	err = m.one.Reload(newcfg)
	if err != nil {
		return err
	}

	m.cfg = newcfg
	w.Write([]byte("reload succeed"))
	return nil
}

func (m *Manager) configHandle(w io.Writer, r *http.Request) error {
	b := bytes.NewBuffer([]byte{})
	m.cfg.inif.WriteTo(b)

	return m.tmpl.ExecuteTemplate(w, "config", map[string]interface{}{
		"Title":     "Config",
		"RuleCount": len(m.cfg.Rule),
		"Source":    string(b.Bytes()),
	})
}

// statistical data api
func (m *Manager) consumeData() {
	accumulate := func(s map[string]*TrafficRecord, name string, endpoint string, upload int64, download int64, now time.Time) {
		o, ok := s[name]
		if ok {
			o.Upload += upload
			o.Download += download
			o.Touch = now
		} else {
			o = &TrafficRecord{
				Name:     name,
				Upload:   upload,
				Download: download,
				Touch:    now,
				Details:  make(map[string]*TrafficRecordDetail),
			}
			s[name] = o
		}

		if len(endpoint) == 0 {
			return
		}

		if d, ok := o.Details[endpoint]; ok {
			d.Upload += upload
			d.Download += download
			d.Touch = now
		} else {
			o.Details[endpoint] = &TrafficRecordDetail{
				EndPoint: endpoint,
				Upload:   upload,
				Download: download,
				Touch:    now,
			}
		}
	}

	for data := range m.dataCh {
		now := time.Now()
		accumulate(m.hosts, data.Src, data.Dst, data.Upload, data.Download, now)
		accumulate(m.websites, data.Dst, data.Src, data.Upload, data.Download, now)
		accumulate(m.proxies, data.Proxy, "", data.Upload, data.Download, now)
	}
}

func (m *Manager) Serve() error {
	http.HandleFunc("/", handleWrapper(m.indexHandle))
	http.HandleFunc("/host/", handleWrapper(m.hostHandle))
	http.HandleFunc("/website/", handleWrapper(m.websiteHandle))
	http.HandleFunc("/proxy/", handleWrapper(m.proxyHandle))
	http.HandleFunc("/dns/", handleWrapper(m.dnsHandle))
	http.HandleFunc("/reload/", handleWrapper(m.reloadHandle))
	http.HandleFunc("/config/", handleWrapper(m.configHandle))
	go m.consumeData()

	logger.Infof("[manager] listen on: %s", m.listen)
	return http.ListenAndServe(m.listen, nil)
}

func NewManager(one *One, cfg *KoneConfig) *Manager {
	if cfg.General.ManagerAddr == "" {
		return nil
	}

	tmpl := template.New("master").Funcs(map[string]interface{}{
		"sumInt64": func(a int64, b int64) int64 {
			return a + b
		},
		"formatNumberComma": func(a int64) string {
			var sign, ret string
			if a == 0 {
				return "0"
			}
			if a < 0 {
				sign, a = "-", -a
			}
			for a > 0 {
				b := a % 1000
				a = a / 1000

				var flag string
				if a > 0 {
					flag = "%03d"
				} else {
					flag = "%d"
				}
				if len(ret) > 0 {
					flag += ",%s"
				} else {
					flag += "%s"
				}
				ret = fmt.Sprintf(flag, b, ret)

			}
			return sign + ret
		},
	})

	return &Manager{
		one:       one,
		cfg:       cfg,
		startTime: time.Now(),
		listen:    cfg.General.ManagerAddr,
		dataCh:    make(chan ConnData),
		hosts:     make(map[string]*TrafficRecord),
		websites:  make(map[string]*TrafficRecord),
		proxies:   make(map[string]*TrafficRecord),
		tmpl:      template.Must(tmpl.Parse(masterTmpl)),
	}
}

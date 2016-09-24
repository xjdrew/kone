package k1

import (
	"html/template"
	"net/http"
)

const masterTmpl = `
{{define "header"}}
<!DOCTYPE HTML>
<html>
<head>
<title>{{.Title}}</title>
<meta charset='utf-8'>
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
`

type Manager struct {
	listen string
	tmpl   *template.Template
}

func (m *Manager) indexHandle(w http.ResponseWriter, r *http.Request) {
	err := m.tmpl.ExecuteTemplate(w, "index", map[string]interface{}{
		"Title": "",
		"URLs": []string{
			"/host",
			"/destination",
		},
	})
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (m *Manager) Serve() error {
	http.HandleFunc("/", m.indexHandle)
	logger.Infof("[manager] listen on: %s", m.listen)
	return http.ListenAndServe(m.listen, nil)
}

func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Listen == "" {
		return nil
	}
	return &Manager{
		listen: cfg.Listen,
		tmpl:   template.Must(template.New("master").Parse(masterTmpl)),
	}
}

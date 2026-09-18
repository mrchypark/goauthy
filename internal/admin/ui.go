package admin

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

//go:embed admin.html admin.css admin.js dashboard.js catalog.js sessions.js collections.js clients.js providers.js blacklist.js events.js templates.js
var uiFS embed.FS

type CSRFTokenProvider func(http.ResponseWriter, *http.Request) bool

type EmailTemplateInfo struct {
	Subject   string
	Header    string
	Text      string
	ClickLink string
	Validity  string
	Expires   string
	Button    string
	Footer    string
}

type EmailTemplateProvider interface {
	Render(typ, lang string) (EmailTemplateInfo, error)
	Types() []string
	Languages(typ string) []string
}

type UI struct {
	browserAdmin BrowserAdministrator
	csrf         CSRFTokenProvider
	templates    EmailTemplateProvider
}

func NewUI(browserAdmin BrowserAdministrator) (*UI, error) {
	if browserAdmin == nil {
		return nil, errors.New("admin UI requires browser administrator")
	}
	return &UI{browserAdmin: browserAdmin}, nil
}

func (u *UI) SetCSRFTokenProvider(provider CSRFTokenProvider) { u.csrf = provider }
func (u *UI) SetTemplateProvider(p EmailTemplateProvider)     { u.templates = p }

func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if r == nil || r.URL == nil || r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Values("Authorization") != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !u.browserAdmin(w, r, false) {
		return
	}
	if r.URL.Path == "/auth/v1/admin/csrf" {
		if u.csrf == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		u.csrf(w, r)
		return
	}
	if r.URL.Path == "/auth/v1/admin/email-templates" {
		u.handleEmailTemplateList(w, r)
		return
	}
	if r.URL.Path == "/auth/v1/admin/email-templates/preview" {
		u.handleEmailTemplatePreview(w, r)
		return
	}
	if r.URL.Path == "/auth/v1/admin/app.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		for _, name := range []string{"dashboard.js", "catalog.js", "sessions.js", "collections.js", "clients.js", "providers.js", "blacklist.js", "events.js", "templates.js", "admin.js"} {
			data, _ := uiFS.ReadFile(name)
			_, _ = w.Write(data)
			_, _ = w.Write([]byte("\n;\n"))
		}
		return
	}
	if r.URL.Path == "/auth/v1/admin/admin.css" {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		data, _ := uiFS.ReadFile("admin.css")
		_, _ = w.Write(data)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, _ := uiFS.ReadFile("admin.html")
	_, _ = w.Write(data)
}

func (u *UI) handleEmailTemplateList(w http.ResponseWriter, r *http.Request) {
	if u.templates == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"types":[],"languages":{}}`))
		return
	}
	types := u.templates.Types()
	langs := make(map[string][]string, len(types))
	for _, t := range types {
		langs[t] = u.templates.Languages(t)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"types": types, "languages": langs})
}

func (u *UI) handleEmailTemplatePreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	typ := r.URL.Query().Get("type")
	lang := r.URL.Query().Get("lang")
	if typ == "" || lang == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<p class=\"error\">type and lang query parameters required</p>"))
		return
	}
	if u.templates == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("<p class=\"error\">email template provider unavailable</p>"))
		return
	}
	info, err := u.templates.Render(typ, lang)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, "<p class=\"error\">%s</p>", template.HTMLEscapeString(err.Error()))
		return
	}
	sampleURL := "https://auth.example.com/reset?token=sample-token-abc123"
	sampleNewEmail := "newuser@example.com"
	sampleOTP := "123456"
	switch typ {
	case "password_reset", "password_new":
		info.ClickLink = strings.ReplaceAll(info.ClickLink, "{{.ResetURL}}", sampleURL)
	case "registered_already":
	case "email_change_confirm":
		info.Text = strings.ReplaceAll(info.Text, "{{.NewEmail}}", sampleNewEmail)
	}
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"><title>Email Preview</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:2em;background:#fff;color:#222}h1{font-size:1.4em}p{margin:.5em 0}footer{margin-top:2em;border-top:1px solid #ddd;padding-top:.5em;font-size:.9em;color:#666}</style>
</head><body>
<h1>%s</h1>
<p>%s</p>
%s
<p>%s</p>
<p>%s <strong>%s</strong></p>
%s
<footer><p>%s</p></footer>
</body></html>`,
		template.HTMLEscapeString(info.Header),
		template.HTMLEscapeString(info.Text),
		func() string {
			if info.ClickLink != "" {
				return fmt.Sprintf("<p><a href=\"%s\" style=\"display:inline-block;padding:.5em 1em;background:#0066cc;color:#fff;text-decoration:none;border-radius:4px\">%s</a></p>", sampleURL, template.HTMLEscapeString(info.Button))
			}
			return ""
		}(),
		template.HTMLEscapeString(info.Validity),
		template.HTMLEscapeString(info.Expires),
		"2024-01-01T00:00:00Z",
		func() string {
			if typ == "otp" {
				return fmt.Sprintf("<p style=\"font-size:2em;font-weight:bold;letter-spacing:0.1em;margin:1em 0\">%s</p>", template.HTMLEscapeString(sampleOTP))
			}
			return ""
		}(),
		template.HTMLEscapeString(info.Footer),
	)
}

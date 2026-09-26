package recovery

import (
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/mrchypark/goauthy/internal/i18n"
)

//go:embed pages.html
var pagesHTML string

//go:embed pages.js
var pagesJS []byte
var recoveryPage = template.Must(template.New("recovery").Parse(pagesHTML))

// Page serves presentation only. Recovery authority stays in the existing APIs.
func (s *Service) Page(w http.ResponseWriter, r *http.Request) {
	mode := "request"
	if strings.HasSuffix(r.URL.Path, "/register") {
		if s.registration == nil || !s.registration.config.Enabled {
			http.NotFound(w, r)
			return
		}
		mode = "register"
	}
	s.renderPage(w, r, mode)
}

func (s *Service) PageScript(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(pagesJS)
}

func (s *Service) renderPage(w http.ResponseWriter, r *http.Request, mode string) {
	securityHeaders(w)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Add("Vary", "Accept")
	w.Header().Add("Vary", "Accept-Language")
	w.Header().Add("Vary", "Cookie")
	issuer, _ := url.Parse(s.issuer)
	blocked := mode == "register" && s.captcha != nil && s.captcha.SiteKey() != ""
	_ = recoveryPage.Execute(w, struct {
		Base, Mode, Language string
		Blocked              bool
	}{strings.TrimRight(issuer.Path, "/"), mode, i18n.UILanguageFromRequest(r), blocked})
}

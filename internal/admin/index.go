// Package admin serves the small browser-admin landing page.
package admin

import (
	"embed"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// BrowserAdministrator is the existing same-origin, peer-bound browser-admin
// authorization boundary supplied by cmd/goauthy. The index is read-only, so
// it always invokes this callback with mutation=false.
type BrowserAdministrator func(http.ResponseWriter, *http.Request, bool) bool

// Route is one concrete, already-mounted administrator GET route. Dynamic
// route patterns are intentionally not accepted: every link on the index must
// point at an actual route, not an invented or user-controlled URL.
type Route struct {
	Label string
	Path  string
}

//go:embed index.html
var indexFS embed.FS

var indexTemplate = template.Must(template.ParseFS(indexFS, "index.html"))

// Handler serves the browser-admin index. It does not access storage or
// expose an API-key authorization path.
type Handler struct {
	browserAdmin BrowserAdministrator
	routes       []Route
}

// NewIndexHandler validates and copies the concrete links used by the index.
func NewIndexHandler(browserAdmin BrowserAdministrator, routes ...Route) (*Handler, error) {
	if browserAdmin == nil {
		return nil, errors.New("admin index requires browser administrator")
	}
	copyRoutes := make([]Route, len(routes))
	copy(copyRoutes, routes)
	seen := make(map[string]struct{}, len(copyRoutes))
	for _, route := range copyRoutes {
		if err := validateRoute(route); err != nil {
			return nil, err
		}
		if _, ok := seen[route.Path]; ok {
			return nil, errors.New("duplicate admin index route")
		}
		seen[route.Path] = struct{}{}
	}
	return &Handler{browserAdmin: browserAdmin, routes: copyRoutes}, nil
}

// Index serves GET /auth/v1/admin. Authentication is delegated only to the
// existing browserAdministrator callback, which enforces the active
// peer-bound session, same-origin request, and issuer-specific cookie.
func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if h == nil || r == nil || r.URL == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// The existing callback rejects all Authorization headers. Keep that
	// invariant local to this page too, so a future callback cannot silently
	// introduce an API-key or bearer fallback.
	if len(r.Header.Values("Authorization")) != 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if h.browserAdmin == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !h.browserAdmin(w, r, false) {
		return
	}
	if err := indexTemplate.Execute(w, struct{ Routes []Route }{Routes: h.routes}); err != nil {
		// The embedded template is parsed at init; this is defensive for future
		// template changes and avoids writing an error body that could be cached.
		return
	}
}

func (h *Handler) headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func validateRoute(route Route) error {
	if strings.TrimSpace(route.Label) == "" || strings.IndexFunc(route.Label, unicode.IsControl) >= 0 {
		return errors.New("invalid admin index route label")
	}
	u, err := url.Parse(route.Path)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != route.Path || !strings.HasPrefix(route.Path, "/auth/v1/") {
		return errors.New("invalid admin index route path")
	}
	if strings.Contains(route.Path, "//") || strings.Contains(route.Path, "\\") || strings.ContainsAny(route.Path, "{}") {
		return errors.New("invalid admin index route path")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(route.Path, "/"), "/") {
		if segment == "." || segment == ".." || segment == "" {
			return errors.New("invalid admin index route path")
		}
	}
	return nil
}

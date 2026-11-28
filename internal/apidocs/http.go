package apidocs

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/mrchypark/goauthy/internal/branding"
	swaggerFiles "github.com/swaggo/files/v2"
)

type Admin func(http.ResponseWriter, *http.Request, bool) bool

type Handler struct {
	docsRoot       string
	basePath       string
	redirectTarget string
	document       []byte
	public         bool
	admin          Admin
	brand          func(context.Context) (branding.Brand, error)
}

func NewHandler(issuer string, document []byte, public bool, admin func(http.ResponseWriter, *http.Request, bool) bool) (http.Handler, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("apidocs issuer must be an absolute http(s) URL without user, query, or fragment")
	}
	if admin == nil && !public {
		return nil, errors.New("apidocs admin callback is required when docs are private")
	}
	prefix := strings.TrimRight(u.EscapedPath(), "/")
	return &Handler{docsRoot: "/auth/v1/docs", basePath: prefix, redirectTarget: prefix + "/auth/v1/docs/", document: append([]byte(nil), document...), public: public, admin: admin}, nil
}

// SetBrandResolver configures common branding for the Swagger UI page.
func (h *Handler) SetBrandResolver(resolve func(context.Context) (branding.Brand, error)) {
	h.brand = resolve
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if r == nil || r.URL == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !h.public && (h.admin == nil || !h.admin(w, r, false)) {
		return
	}
	switch r.URL.Path {
	case h.docsRoot:
		h.redirectSlash(w, r)
	case h.docsRoot + "/", h.docsRoot + "/index.html":
		h.index(w, r)
	case h.docsRoot + "/openapi.json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(h.document)
		}
	case h.docsRoot + "/swagger-ui.css":
		h.asset(w, r, "swagger-ui.css", "text/css; charset=utf-8")
	case h.docsRoot + "/index.css":
		h.asset(w, r, "index.css", "text/css; charset=utf-8")
	case h.docsRoot + "/theme.css":
		h.themeCSS(w, r)
	case h.docsRoot + "/swagger-ui-bundle.js", h.docsRoot + "/swagger-ui-standalone-preset.js":
		h.asset(w, r, strings.TrimPrefix(r.URL.Path, h.docsRoot+"/"), "application/javascript; charset=utf-8")
	case h.docsRoot + "/swagger-initializer.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `window.onload=function(){window.ui=SwaggerUIBundle({url:"./openapi.json",validatorUrl:null,queryConfigEnabled:false,dom_id:"#swagger-ui",deepLinking:true,presets:[SwaggerUIBundle.presets.apis,SwaggerUIStandalonePreset],layout:"BaseLayout",supportedSubmitMethods:[]});};`)
		}
	case h.docsRoot + "/favicon-16x16.png", h.docsRoot + "/favicon-32x32.png":
		h.asset(w, r, strings.TrimPrefix(r.URL.Path, h.docsRoot+"/"), "image/png")
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (h *Handler) redirectSlash(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", h.redirectTarget)
	w.WriteHeader(http.StatusPermanentRedirect)
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		brand := branding.ResolveOptional(r.Context(), h.brand)
		themeLink := ""
		if strings.HasPrefix(brand.ThemeURL, "/") && !strings.HasPrefix(brand.ThemeURL, "//") {
			themeLink = fmt.Sprintf(`<link rel="stylesheet" href="%s%s">`, html.EscapeString(h.basePath), html.EscapeString(brand.ThemeURL))
		}
		_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s · API Docs</title><link rel="stylesheet" href="./swagger-ui.css"><link rel="stylesheet" href="./index.css"><link rel="stylesheet" href="%s/auth/v1/ui/brand.css"><link rel="stylesheet" href="%s/auth/v1/theme/global.css">%s<link rel="stylesheet" href="./theme.css"></head><body><div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script><script src="./swagger-ui-standalone-preset.js"></script><script src="./swagger-initializer.js"></script></body></html>`,
			html.EscapeString(brand.Name), html.EscapeString(h.basePath), html.EscapeString(h.basePath), themeLink)
	}
}

func (h *Handler) themeCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = fmt.Fprint(w, swaggerThemeCSS)
	}
}

const swaggerThemeCSS = `body { background: hsl(var(--bg)); color: hsl(var(--text-high)); font-family: var(--brand-font, Geist, Pretendard, system-ui, sans-serif); }
.swagger-ui { color: hsl(var(--text-high)); font-family: inherit; }
.swagger-ui .topbar { background-color: hsl(var(--bg-high)); border-bottom: 1px solid hsl(var(--text) / .22); }
.swagger-ui .topbar .download-url-wrapper input[type=text] { background: hsl(var(--bg)); color: hsl(var(--text-high)); border-color: hsl(var(--text) / .4); }
.swagger-ui .info .title, .swagger-ui .info p, .swagger-ui .info li, .swagger-ui .info table,
.swagger-ui .opblock-tag, .swagger-ui .opblock .opblock-summary-description, .swagger-ui .opblock-description-wrapper p,
.swagger-ui .parameter__name, .swagger-ui .parameter__type, .swagger-ui .response-col_status,
.swagger-ui .response-col_description, .swagger-ui table thead tr th, .swagger-ui table thead tr td,
.swagger-ui .model-title, .swagger-ui .model, .swagger-ui label, .swagger-ui .tab li { color: hsl(var(--text-high)); }
.swagger-ui .info a, .swagger-ui a.nostyle { color: hsl(var(--action)); }
.swagger-ui .scheme-container { background: hsl(var(--bg-high)); box-shadow: none; border-bottom: 1px solid hsl(var(--text) / .22); }
.swagger-ui .opblock, .swagger-ui .models, .swagger-ui section.models { border-color: hsl(var(--text) / .22); background: hsl(var(--bg-high) / .45); }
.swagger-ui .opblock .opblock-section-header { background: hsl(var(--bg-high)); }
.swagger-ui .btn { color: hsl(var(--text-high)); border-color: hsl(var(--text) / .4); }
.swagger-ui .btn.authorize { color: hsl(var(--action)); border-color: hsl(var(--action)); }
.swagger-ui .btn.execute { background-color: hsl(var(--action)); color: var(--btn-text); border-color: hsl(var(--action)); }
.swagger-ui input, .swagger-ui select, .swagger-ui textarea { background: hsl(var(--bg)); color: hsl(var(--text-high)); border-color: hsl(var(--text) / .4); }
@media (prefers-color-scheme: dark) {
  .swagger-ui .opblock-summary-method, .swagger-ui .btn svg, .swagger-ui .expand-methods svg, .swagger-ui .expand-operation svg, .swagger-ui .model-toggle::after { filter: brightness(1.1); }
}
html[data-theme="dark"] .swagger-ui svg { fill: currentColor; }
`

func (h *Handler) asset(w http.ResponseWriter, r *http.Request, name, contentType string) {
	b, err := fs.ReadFile(swaggerFiles.FS, name)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(b)
	}
}

func (h *Handler) headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
}

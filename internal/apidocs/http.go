package apidocs

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	swaggerFiles "github.com/swaggo/files/v2"
)

type Admin func(http.ResponseWriter, *http.Request, bool) bool

type Handler struct {
	docsRoot       string
	redirectTarget string
	document       []byte
	public         bool
	admin          Admin
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
	return &Handler{docsRoot: "/auth/v1/docs", redirectTarget: prefix + "/auth/v1/docs/", document: append([]byte(nil), document...), public: public, admin: admin}, nil
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
		_, _ = fmt.Fprint(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Swagger UI</title><link rel="stylesheet" href="./swagger-ui.css"><link rel="stylesheet" href="./index.css"></head><body><div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script><script src="./swagger-ui-standalone-preset.js"></script><script src="./swagger-initializer.js"></script></body></html>`)
	}
}

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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
}

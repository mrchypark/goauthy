// Package ui integrates Ely's embedded components with GoAuthy's issuer and theme.
package ui

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"path"
	"strings"
	"time"

	ely "github.com/mrchypark/elysdui/ui/gohtmx"
)

const AssetPath = "/auth/v1/ui/"

//go:embed brand.css
var brandCSS []byte

var stylesheets = []string{
	"app.css", "ely-controls.css", "ely-patterns.css", "brand.css",
}

// NewTemplates loads the actual Ely components, a CSS-only goauthy-head, and the
// shared goauthy-brand header lockup. Pass Base="" to goauthy-brand when LogoURL
// is already issuer-prefixed; otherwise pass the issuer base path.
// Keep custom brand stylesheets after the head. Scripts remain page-owned.
func NewTemplates(name string) (*template.Template, error) {
	t, err := ely.NewTemplates()
	if err != nil {
		return nil, err
	}
	return t.New(name).Funcs(template.FuncMap{
		"uiStylesheets": func() []string { return stylesheets },
		"uiAssetBase":   assetBase,
	}).Parse(`{{define "goauthy-head"}}{{$base := uiAssetBase .}}{{range uiStylesheets}}<link rel="stylesheet" href="{{$base}}{{.}}">
{{end}}{{end}}{{define "goauthy-brand"}}{{$name := "GoAuthy"}}{{if .Name}}{{$name = .Name}}{{end}}{{if .LogoURL}}<img class="client-login-logo" src="{{.Base}}{{.LogoURL}}" alt="{{$name}}">{{else}}<span class="brand-symbol" aria-hidden="true"></span><span>{{$name}}</span>{{end}}{{end}}`)
}

func assetBase(prefix string) (string, error) {
	if strings.HasPrefix(prefix, "//") {
		return "", fmt.Errorf("invalid UI issuer path %q", prefix)
	}
	prefix = strings.TrimRight(prefix, "/")
	if prefix != "" && (!strings.HasPrefix(prefix, "/") || path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "\\?#%\r\n\t")) {
		return "", fmt.Errorf("invalid UI issuer path %q", prefix)
	}
	return prefix + AssetPath, nil
}

// BindAssets mounts only the CSS and fonts used by the shared head. The outer
// issuerPathMiddleware removes the issuer prefix before requests reach this mux.
func BindAssets(mux *http.ServeMux) error {
	names := append([]string(nil), stylesheets...)
	names = append(names,
		"geist.woff2", "geist-mono.woff2", "pretendard.woff2",
		"ely/fonts/Inter-Regular.ttf", "ely/fonts/Inter-Medium.ttf",
		"ely/fonts/Inter-SemiBold.ttf", "ely/fonts/Inter-Italic.ttf",
		"ely/fonts/JetBrainsMono-Regular.ttf", "ely/fonts/JetBrainsMono-Medium.ttf",
	)
	for _, name := range names {
		body := brandCSS
		if name != "brand.css" {
			var err error
			body, err = ely.Files.ReadFile("assets/" + name)
			if err != nil {
				return fmt.Errorf("read Ely asset %s: %w", name, err)
			}
		}
		contentType := "font/woff2"
		if strings.HasSuffix(name, ".ttf") {
			contentType = "font/ttf"
		} else if strings.HasSuffix(name, ".css") {
			contentType = "text/css; charset=utf-8"
			// Ely's root font URLs must resolve within the issuer namespace.
			body = bytes.ReplaceAll(body, []byte("/assets/"), nil)
		}
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(body))
		mux.Handle("GET "+AssetPath+name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "public, no-cache")
			w.Header().Set("ETag", etag)
			http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
		}))
	}
	return nil
}

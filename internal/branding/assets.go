package branding

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed assets/*
var brandAssets embed.FS

// BrandAssetHandler serves only files bundled with the application.
func BrandAssetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveBrandAsset(w, r, r.PathValue("name"))
	})
}

func DefaultFaviconHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveBrandAsset(w, r, "gateway.svg")
	})
}

func serveBrandAsset(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	contentTypes := map[string]string{"brand.css": "text/css", "locale.js": "text/javascript; charset=utf-8", "manrope.ttf": "font/ttf", "pretendard.woff2": "font/woff2", "gateway.svg": "image/svg+xml"}
	contentType, ok := contentTypes[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := brandAssets.ReadFile("assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", globalCSSCacheControl)
	if name == "brand.css" || name == "locale.js" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

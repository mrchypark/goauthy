package branding

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBundledBrandAssets(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /auth/v1/branding/{name}", BrandAssetHandler())
	for _, name := range []string{"brand.css", "locale.js", "manrope.ttf", "pretendard.woff2", "gateway.svg"} {
		for _, method := range []string{"GET", "HEAD"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(method, "/auth/v1/branding/"+name, nil))
			if (name == "brand.css" || name == "locale.js") && w.Header().Get("Cache-Control") != "no-cache" {
				t.Fatalf("unversioned UI asset must revalidate: %s", name)
			}
			if w.Code != 200 || w.Header().Get("Content-Type") == "" || (method == "GET" && w.Body.Len() == 0) || (method == "HEAD" && w.Body.Len() != 0) {
				t.Fatalf("%s %s: %d %v", method, name, w.Code, w.Header())
			}
		}
	}
	for _, name := range []string{"missing", "../global.css", "Manrope-OFL.txt"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		BrandAssetHandler().ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("unexpected asset %s: %d", name, w.Code)
		}
	}
	w := httptest.NewRecorder()
	DefaultFaviconHandler().ServeHTTP(w, httptest.NewRequest("GET", "/favicon.ico", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("default favicon: %d", w.Code)
	}
}

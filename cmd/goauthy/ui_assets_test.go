package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/ui"
)

func TestUIAssetsRespectIssuerNamespace(t *testing.T) {
	for _, prefix := range []string{"", "/tenant", "/tenant/nested"} {
		t.Run(prefix, func(t *testing.T) {
			mux := http.NewServeMux()
			if err := ui.BindAssets(mux); err != nil {
				t.Fatal(err)
			}
			h := issuerPathMiddleware(mux, "https://id.example.test"+prefix)
			for _, name := range []string{"app.css", "brand.css", "geist.woff2"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", prefix+ui.AssetPath+name, nil))
				if w.Code != 200 || w.Body.Len() == 0 {
					t.Fatalf("%s: %d", name, w.Code)
				}
			}
			for _, path := range []string{prefix + ui.AssetPath + "missing.css", prefix + ui.AssetPath + "", "/assets/app.css"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				if w.Code != 404 {
					t.Fatalf("unexpected path %s: %d", path, w.Code)
				}
			}
			if prefix != "" {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", ui.AssetPath+"app.css", nil))
				if w.Code != 404 {
					t.Fatalf("unprefixed asset leaked: %d", w.Code)
				}
			}
		})
	}
}

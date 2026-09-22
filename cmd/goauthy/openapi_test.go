package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apidocs"
)

func TestSwaggerConfig(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		enable, public string
		want           swaggerConfig
	}{
		{"", "", swaggerConfig{}},
		{"true", "", swaggerConfig{Enabled: true}},
		{"", "true", swaggerConfig{Public: true}},
		{"true", "true", swaggerConfig{Enabled: true, Public: true}},
	} {
		got, err := swaggerConfigFromEnv(func(name string) string {
			if name == "GOAUTHY_SWAGGER_UI_ENABLE" {
				return tc.enable
			}
			return tc.public
		})
		if err != nil || got != tc.want {
			t.Fatalf("config=%+v err=%v want=%+v", got, err, tc.want)
		}
	}
	for _, name := range []string{"GOAUTHY_SWAGGER_UI_ENABLE", "GOAUTHY_SWAGGER_UI_PUBLIC"} {
		_, err := swaggerConfigFromEnv(func(key string) string {
			if key == name {
				return "not-a-boolean"
			}
			return ""
		})
		if err == nil {
			t.Fatalf("accepted invalid %s", name)
		}
	}
}

func TestSwaggerProductionMountAndIssuerPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		config     swaggerConfig
		authorized bool
		status     int
	}{
		{"disabled", swaggerConfig{}, true, 404},
		{"public-does-not-enable", swaggerConfig{Public: true}, true, 404},
		{"private-anonymous", swaggerConfig{Enabled: true}, false, 401},
		{"private-admin", swaggerConfig{Enabled: true}, true, 200},
		{"public", swaggerConfig{Enabled: true, Public: true}, false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			calls := 0
			err := mountSwaggerRoutes(mux, tc.config, "https://id.example.test/tenant", apidocs.Features{}, func(w http.ResponseWriter, _ *http.Request, mutation bool) bool {
				calls++
				if mutation {
					t.Fatal("documentation requested mutation authorization")
				}
				if !tc.authorized {
					w.WriteHeader(http.StatusUnauthorized)
				}
				return tc.authorized
			})
			if err != nil {
				t.Fatal(err)
			}
			h := issuerPathMiddleware(mux, "https://id.example.test/tenant")
			for _, suffix := range []string{"/", "/openapi.json", "/swagger-ui-bundle.js", "/swagger-initializer.js"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tenant/auth/v1/docs"+suffix, nil))
				if w.Code != tc.status {
					t.Fatalf("%s status=%d want=%d", suffix, w.Code, tc.status)
				}
				if tc.status == 200 && w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("docs may be cached")
				}
			}
			if tc.config.Enabled && !tc.config.Public && calls != 4 {
				t.Fatalf("auth calls=%d", calls)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/v1/docs/openapi.json", nil))
			if w.Code != 404 {
				t.Fatalf("unprefixed documentation leaked: %d", w.Code)
			}
			if tc.status == 200 {
				w = httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, "/tenant/auth/v1/docs", nil)
				r.Host = "untrusted.example.test"
				h.ServeHTTP(w, r)
				if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "/tenant/auth/v1/docs/" {
					t.Fatalf("redirect=%d %s", w.Code, w.Header().Get("Location"))
				}
				w = httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tenant/auth/v1/docs/?url=https://untrusted.example.test", nil))
				if w.Code != 400 || strings.Contains(w.Body.String(), "untrusted.example.test") {
					t.Fatal("accepted remote configuration query")
				}
			}
		})
	}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/admin"
	"github.com/mrchypark/goauthy/internal/browser"
)

func TestAdminUICSRFUsesAuthorizedIssuerCookie(t *testing.T) {
	t.Parallel()
	issuer := "https://issuer.example.test"
	name, err := browser.CookieName(issuer)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name    string
		allowed bool
		cookie  *http.Cookie
		status  int
	}{
		{"missing", true, nil, 401},
		{"wrong issuer", true, &http.Cookie{Name: "unrelated", Value: raw}, 401},
		{"malformed", true, &http.Cookie{Name: name, Value: "invalid"}, 401},
		{"denied", false, &http.Cookie{Name: name, Value: raw}, 401},
		{"authorized", true, &http.Cookie{Name: name, Value: raw}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ui, err := admin.NewUI(func(w http.ResponseWriter, _ *http.Request, mutation bool) bool {
				if mutation {
					t.Fatal("token read is not a mutation")
				}
				if !tc.allowed {
					w.WriteHeader(401)
				}
				return tc.allowed
			})
			if err != nil {
				t.Fatal(err)
			}
			ui.SetCSRFTokenProvider(adminCSRFTokenProvider(issuer))
			r := httptest.NewRequest(http.MethodGet, "/auth/v1/admin/csrf", nil)
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}
			w := httptest.NewRecorder()
			ui.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), raw) {
				t.Fatalf("status=%d headers=%v unsafe body=%s", w.Code, w.Header(), w.Body.String())
			}
			if tc.status == 200 {
				var out map[string]string
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 1 || browser.ValidateCSRFToken(raw, out["token"]) != nil {
					t.Fatal("invalid CSRF response")
				}
			}
		})
	}
}

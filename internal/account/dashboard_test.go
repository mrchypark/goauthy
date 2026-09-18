package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
)

func TestDashboardCurrentAccountBoundary(t *testing.T) {
	h, sessions, _, cookie, csrf := testPasswordHandler(t)
	for _, path := range []string{"/account", "/account/data", "/account/app.js", "/account/connections.js", "/account/connection-grants.js", "/account/devices.js", "/account/account.css"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.Dashboard(w, r)
			if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatalf("status=%d headers=%v", w.Code, w.Header())
			}
			if strings.Contains(w.Body.String(), cookie.Value) || strings.Contains(w.Body.String(), "$argon2") {
				t.Fatal("dashboard exposed credential material")
			}
			if path == "/account/data" {
				var data map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
					t.Fatal(err)
				}
				var actual string
				if json.Unmarshal(data["csrf_token"], &actual) != nil || actual != csrf {
					t.Fatal("issuer-bound CSRF mismatch")
				}
				if json.Unmarshal(data["subject"], &actual) != nil || actual != "subject-1" {
					t.Fatal("wrong account projection")
				}
				if _, ok := data["password_phc"]; ok {
					t.Fatal("credential field exposed")
				}
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		code   int
	}{
		{"anonymous", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"bearer-with-cookie", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ignored") }, 401},
		{"empty-auth-with-cookie", func(r *http.Request) { r.Header["Authorization"] = []string{""} }, 401},
		{"api-key-with-cookie", func(r *http.Request) { r.Header.Set("Authorization", "API-Key ignored") }, 401},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "subject=other" }, 404},
		{"unknown-page", func(r *http.Request) { r.URL.Path = "/account/unknown" }, 404},
		{"method", func(r *http.Request) { r.Method = http.MethodPost }, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/account/data", nil)
			r.AddCookie(cookie)
			tc.mutate(r)
			w := httptest.NewRecorder()
			h.Dashboard(w, r)
			if w.Code != tc.code {
				t.Fatalf("status=%d want=%d", w.Code, tc.code)
			}
			if strings.Contains(w.Body.String(), csrf) {
				t.Fatal("denial exposed CSRF")
			}
		})
	}
	if err := sessions.RevokeSession(t.Context(), cookie.Value); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/account/data", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.Dashboard(w, r)
	if w.Code != 401 {
		t.Fatalf("revoked session status=%d", w.Code)
	}
}

func TestDashboardIssuerPathAssets(t *testing.T) {
	h, _, _, cookie, _ := testPasswordHandler(t)
	h.issuer = "https://issuer.example.test/realm"
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		t.Fatal(err)
	}
	cookie.Name = name
	r := httptest.NewRequest(http.MethodGet, "/account", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.Dashboard(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `src="/realm/account/app.js"`) || !strings.Contains(w.Body.String(), `href="/realm/account/account.css"`) {
		t.Fatalf("issuer-prefixed asset links absent, status=%d", w.Code)
	}
}

func TestDashboardConversionCapability(t *testing.T) {
	h, _, _, _, _, _ := testPasskeyAccountHandler(t)
	for _, tc := range []struct {
		method, peer string
		want         bool
	}{
		{"pwd", "203.0.113.8", false},
		{"webauthn", "203.0.113.8", false},
		{"external", "203.0.113.8", false},
		{"mfa", "", false},
		{"mfa", "203.0.113.8", true},
	} {
		t.Run(tc.method+tc.peer, func(t *testing.T) {
			issued, err := h.browser.CreateSession(t.Context(), "subject-1", tc.method, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), tc.peer)
			if err != nil {
				t.Fatal(err)
			}
			cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/account/data", nil)
			r.AddCookie(cookie)
			r = r.WithContext(browser.ContextWithPeerIP(r.Context(), tc.peer))
			read := func(want bool) {
				t.Helper()
				w := httptest.NewRecorder()
				h.Dashboard(w, r)
				var data struct {
					Features map[string]bool `json:"features"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || w.Code != http.StatusOK {
					t.Fatalf("dashboard status=%d decode=%v", w.Code, err)
				}
				got, present := data.Features["passkey_conversion"]
				if !present || got != want {
					t.Fatalf("conversion capability=%v present=%v want=%v", got, present, want)
				}
			}
			read(tc.want)
			service := h.passkeys
			h.passkeys = nil
			read(false)
			h.passkeys = service
		})
	}
}

package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHomeSessionDestination(t *testing.T) {
	h, _, _, cookie, _ := testPasswordHandler(t)
	for _, tc := range []struct {
		name                              string
		signedIn, admin, bearer, forceMFA bool
		path                              string
		code                              int
	}{
		{"anonymous", false, false, false, false, "/account/login", 303},
		{"member", true, false, false, false, "/account", 303},
		{"admin", true, true, false, false, "/auth/v1/admin/dashboard", 303},
		{"admin needs MFA", true, true, false, true, "/account/login", 303},
		{"no bearer fallback", true, true, true, false, "", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.ConfigureAdminForceMFA(tc.forceMFA)
			h.isAdmin = func(context.Context, string) (bool, error) { return tc.admin, nil }
			r := httptest.NewRequest(http.MethodGet, "/?redirect=https://untrusted.test", nil)
			if tc.signedIn {
				r.AddCookie(cookie)
			}
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer invalid")
			}
			w := httptest.NewRecorder()
			h.Home(w, r)
			if w.Code != tc.code {
				t.Fatalf("status=%d", w.Code)
			}
			if tc.path != "" && w.Header().Get("Location") != h.issuer+tc.path {
				t.Fatal(w.Header())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("session redirect must not be cached")
			}
		})
	}
}

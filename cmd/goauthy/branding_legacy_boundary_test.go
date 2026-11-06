package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/rbac"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLegacyBrandingUsesRealBrowserAdminAndCSRF(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "legacy-browser-boundary", DataDir: migratedDataDir(t, "legacy-browser-boundary")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := testHash(context.Background(), []byte("synthetic test password"))
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"legacy-admin", "legacy-member"} {
		if _, err := identities.BootstrapUser(ctx, subject, subject+"@example.test", phc); err != nil {
			t.Fatal(err)
		}
	}
	roles := rbac.NewStore(db)
	if _, err := roles.EnsureBootstrapPrincipal(ctx, "legacy-admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://id.example.test"
	makeSession := func(subject string) (*http.Cookie, string) {
		issued, err := sessions.CreateSession(ctx, subject, "pwd", time.Now().Add(time.Hour), "")
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := browser.SessionCookie(issuer, issued.Token, issued.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		csrf, err := browser.DeriveCSRFToken(issued.Token)
		if err != nil {
			t.Fatal(err)
		}
		return cookie, csrf
	}
	admin, csrf := makeSession("legacy-admin")
	member, memberCSRF := makeSession("legacy-member")
	themes, _ := branding.NewThemeStore(db)
	keys, _ := apikey.NewStore(db)
	handler, err := branding.NewThemeHandler(themes, keys, browserAdministrator(roles, sessions, identities, issuer), func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	read := httptest.NewRequest(http.MethodGet, issuer+"/auth/v1/branding/legacy", nil)
	read.AddCookie(admin)
	w := httptest.NewRecorder()
	handler.LegacyStatus(w, read)
	if w.Code != http.StatusOK {
		t.Fatalf("admin read status=%d", w.Code)
	}
	for _, test := range []struct {
		name       string
		cookie     *http.Cookie
		csrf, site string
	}{
		{name: "anonymous"}, {name: "missing csrf", cookie: admin}, {name: "wrong csrf", cookie: admin, csrf: "invalid"},
		{name: "cross site", cookie: admin, csrf: csrf, site: "cross-site"}, {name: "member", cookie: member, csrf: memberCSRF},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, issuer+"/auth/v1/branding/legacy/resolve", bytes.NewBufferString(`{"confirm_client_ownership":true,"copy_theme":false,"copy_logo":false}`))
			if test.cookie != nil {
				r.AddCookie(test.cookie)
			}
			r.Header.Set("X-CSRF-Token", test.csrf)
			r.Header.Set("Sec-Fetch-Site", test.site)
			w := httptest.NewRecorder()
			handler.ResolveLegacy(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("denied request status=%d", w.Code)
			}
		})
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM branding_legacy_resolution", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatal("denied requests changed resolution")
	}
	r := httptest.NewRequest(http.MethodPost, issuer+"/auth/v1/branding/legacy/resolve", bytes.NewBufferString(`{"confirm_client_ownership":true,"copy_theme":false,"copy_logo":false}`))
	r.AddCookie(admin)
	r.Header.Set("X-CSRF-Token", csrf)
	w = httptest.NewRecorder()
	handler.ResolveLegacy(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("valid admin CSRF status=%d", w.Code)
	}
}

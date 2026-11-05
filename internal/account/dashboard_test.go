package account

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func TestDashboardDataModeFailureAndDueTouch(t *testing.T) {
	h, _, db, cookie, _, _ := testConversionHandler(t)
	digest, err := browser.CanonicalTokenDigest(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	oldSeen := time.Now().Add(-11 * time.Second).UnixMilli()
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "dashboard-due", SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms=? WHERE token_digest=?`, Args: []any{oldSeen, digest}}); err != nil {
		t.Fatal(err)
	}
	read := func(path string, status int) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(cookie)
		r = r.WithContext(browser.ContextWithPeerIP(r.Context(), "203.0.113.8"))
		w := httptest.NewRecorder()
		h.Dashboard(w, r)
		if w.Code != status {
			t.Fatalf("%s status=%d want=%d", path, w.Code, status)
		}
	}
	read("/account/data", http.StatusOK)
	seen, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT last_seen_at_unix_ms FROM browser_sessions WHERE token_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(seen.Rows) != 1 || seen.Rows[0][0].(int64) <= oldSeen {
		t.Fatalf("due account read did not touch session: %v", err)
	}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "dashboard-mode-missing", SQL: `DELETE FROM identity_authentication_modes WHERE subject='subject-1'`}); err != nil {
		t.Fatal(err)
	}
	read("/account/data", http.StatusServiceUnavailable)
	read("/account", http.StatusOK)
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "dashboard-disabled", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='subject-1'`}); err != nil {
		t.Fatal(err)
	}
	read("/account/data", http.StatusUnauthorized)
}

func TestDashboardCurrentAccountBoundary(t *testing.T) {
	t.Parallel()
	h, sessions, _, cookie, csrf := testPasswordHandler(t)
	for _, path := range []string{"/account", "/account/data", "/account/app.js", "/account/locale.js", "/account/connections.js", "/account/connection-grants.js", "/account/devices.js", "/account/account.css"} {
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

func TestDashboardCommonBrandEscapingAndIssuerPaths(t *testing.T) {
	h, _, _, cookie, _ := testPasswordHandler(t)
	h.issuer = "http://localhost/tenant"
	cookie.Name, _ = browser.CookieName(h.issuer)
	h.SetBrandResolver(func(context.Context) (branding.Brand, error) {
		return branding.Brand{Name: `ID "<operator>"`, LogoURL: "/auth/v1/clients/rauthy/logo?updated=7", ThemeURL: "/auth/v1/theme/rauthy/9"}, nil
	})
	r := httptest.NewRequest("GET", "/account", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.Dashboard(w, r)
	for _, want := range []string{`ID &#34;&lt;operator&gt;&#34;`, `src="/tenant/auth/v1/clients/rauthy/logo?updated=7"`, `href="/tenant/auth/v1/theme/rauthy/9"`} {
		if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("status=%d missing %q body=%s", w.Code, want, w.Body.String())
		}
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "img-src 'self'") || strings.Contains(w.Body.String(), `<operator>`) {
		t.Fatal("unsafe brand projection")
	}
}

func TestDashboardIssuerPathAssets(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestFederatedPasswordlessAccountExposesActualCapabilities(t *testing.T) {
	h, db, _, _, _, _ := testPasskeyAccountHandler(t)
	const providerID = "AbCdEfGhIjKlMnOpQrStUvWx"
	const issuer = "https://accounts.google.com"
	const clientID = "account-test-client"
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{
		RequestID: "account-federated-capability-provider",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,use_pkce,client_secret_basic,client_secret_post,auto_onboarding,auto_link) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, Args: []any{
				providerID, int64(1), "synthetic-provider", "oidc", issuer,
				"https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
				"https://openidconnect.googleapis.com/v1/userinfo", clientID, nil, "openid email profile",
				int64(1), int64(1), int64(0), int64(1), int64(0),
			}},
			{SQL: `INSERT INTO auth_provider_runtime_versions(provider_id, version) VALUES(?, ?)`, Args: []any{providerID, "v1"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	namespace := upstreamprovider.ComputeNamespace(issuer, clientID)
	created, err := h.identity.CreateFederatedIdentity(t.Context(), identity.FederatedCreationInput{
		Subject: upstreamprovider.SubjectResult{ProviderID: providerID, Subject: "synthetic-upstream-subject", IdentityNamespace: namespace},
		Config:  identity.FederatedConfigSnapshot{Source: "registry", Version: "v1", Issuer: issuer, ClientID: clientID, Kind: "oidc", AutoOnboarding: true},
		Email:   "federated@example.test", EmailVerified: true,
	})
	if err != nil || !created.Created {
		t.Fatalf("CreateFederatedIdentity result=%#v err=%v", created, err)
	}
	issued, err := h.browser.CreateSession(t.Context(), created.Subject, "external", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /account/data", h.Dashboard)
	mux.HandleFunc("GET /auth/v1/users/{subject}/webauthn", h.ListPasskeys)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := server.Client()
	request := func(path string) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.AddCookie(cookie)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := request("/account/data")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("account data status=%d", response.StatusCode)
	}
	var data struct {
		Features map[string]bool `json:"features"`
	}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data.Features["password"] || !data.Features["passkeys"] {
		t.Fatalf("federated passwordless capabilities=%v", data.Features)
	}
	response = request("/auth/v1/users/" + created.Subject + "/webauthn")
	defer response.Body.Close()
	var passkeys []PasskeyResponse
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&passkeys) != nil || len(passkeys) != 0 {
		t.Fatalf("empty federated passkey inventory status=%d items=%v", response.StatusCode, passkeys)
	}
}

func TestDashboardNavigationAndLanguage(t *testing.T) {
	h, _, _, cookie, _ := testPasswordHandler(t)
	h.issuer = "http://localhost/tenant"
	cookie.Name, _ = browser.CookieName(h.issuer)
	h.isAdmin = func(context.Context, string) (bool, error) { return true, nil }
	r := httptest.NewRequest("GET", "/account", nil)
	r.AddCookie(cookie)
	r.AddCookie(&http.Cookie{Name: "goauthy_ui_locale", Value: "ko"})
	w := httptest.NewRecorder()
	h.Dashboard(w, r)
	for _, value := range []string{`lang="ko"`, `href="/tenant/auth/v1/admin/dashboard"`, `data-language-select`} {
		if !strings.Contains(w.Body.String(), value) {
			t.Fatalf("status %d missing %s", w.Code, value)
		}
	}
	h.isAdmin = func(context.Context, string) (bool, error) { return false, nil }
	w = httptest.NewRecorder()
	h.Dashboard(w, r)
	if strings.Contains(w.Body.String(), `href="/tenant/auth/v1/admin/dashboard"`) {
		t.Fatal("non-admin sees administrator link")
	}
	r = httptest.NewRequest("GET", "/account", nil)
	r.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	h.Dashboard(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/tenant/account/login" {
		t.Fatal("anonymous browser has no sign-in path", w.Code, w.Header())
	}
}

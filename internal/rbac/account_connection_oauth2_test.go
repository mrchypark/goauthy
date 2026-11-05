package rbac

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/saas"
)

func oauthCredentialHTTPStore(t *testing.T, store *Store) *saas.CredentialStore {
	t.Helper()
	d := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 41)
	}
	if err := os.WriteFile(filepath.Join(d, "master"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	kr, err := oidc.LoadKeyring(d, "master")
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := saas.NewCredentialStore(store.db, kr)
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func TestAccountConnectionOAuth2Boundary(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindSaaSProviderStore(providerHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}

	start := providerRequest(http.MethodPost, "/auth/v1/account/connections/collection/connection/oauth2/provider", `{"provider_id":"provider"}`, cookie, csrf, "")
	start.SetPathValue("collection_id", "collection")
	start.SetPathValue("connection_id", "connection")
	start.SetPathValue("provider_id", "provider")
	w := httptest.NewRecorder()
	h.AccountConnectionOAuth2Start(w, start)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown provider status=%d", w.Code)
	}

	for name, setup := range map[string]func(*http.Request){
		"api key": func(r *http.Request) { r.Header.Set("Authorization", "API-Key invalid") },
		"bearer":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer invalid") },
		"duplicate authorization": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer invalid")
			r.Header.Add("Authorization", "Bearer second")
		},
		"csrf missing":     func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"duplicate cookie": func(r *http.Request) { r.AddCookie(cookie) },
	} {
		t.Run(name, func(t *testing.T) {
			r := providerRequest(http.MethodPost, "/auth/v1/account/connections/collection/connection/oauth2/provider", `{"provider_id":"provider"}`, cookie, csrf, "")
			r.SetPathValue("collection_id", "collection")
			r.SetPathValue("connection_id", "connection")
			r.SetPathValue("provider_id", "provider")
			setup(r)
			w := httptest.NewRecorder()
			h.AccountConnectionOAuth2Start(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	callback := httptest.NewRequest(http.MethodGet, "/auth/v1/account/connections/collection/connection/oauth2/provider/callback?error=access_denied&error_description=cancelled", nil)
	callback.AddCookie(cookie)
	callback.SetPathValue("collection_id", "collection")
	callback.SetPathValue("connection_id", "connection")
	callback.SetPathValue("provider_id", "provider")
	callback.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.AccountConnectionOAuth2Callback(w, callback)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback denial status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAccountConnectionOAuth2CallbackGoogleParameters(t *testing.T) {
	h, store, cookie, _ := membershipHTTPFixture(t)
	providers := providerHTTPStore(t, store)
	if err := h.BindSaaSProviderStore(providers); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	_, err := providers.Create(t.Context(), saas.ProviderInput{
		ID: "google-synthetic", Name: "Google synthetic", Kind: "oauth2", Enabled: true,
		ClientID: "synthetic-client", ClientSecret: "synthetic-secret",
		CallbackURI:      h.issuer + "/auth/v1/saas/callback/google-synthetic",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token", AuthStyle: "params",
		IdentityEndpoint: "https://openidconnect.googleapis.com/v1/userinfo", SubjectField: "sub",
		Scopes: []string{"openid", "email", "profile"},
	}, func() (string, []any) { return "1", nil })
	if err != nil {
		t.Fatal(err)
	}
	const base = "state=synthetic-unissued-state&iss=https%3A%2F%2Faccounts.google.com&code=synthetic-code"
	for _, tc := range []struct {
		name, query string
		want        int
	}{
		{"Google metadata", base + "&scope=openid+email+profile&authuser=0&prompt=consent", http.StatusNotFound},
		{"unknown metadata", base + "&hd=example.com&extension=https%3A%2F%2Fevil.example", http.StatusNotFound},
		{"missing issuer", "state=synthetic-unissued-state&code=synthetic-code", http.StatusBadRequest},
		{"wrong issuer", strings.Replace(base, "accounts.google.com", "evil.example", 1), http.StatusBadRequest},
		{"duplicate state", base + "&%73tate=other", http.StatusBadRequest},
		{"duplicate code", base + "&code=other", http.StatusBadRequest},
		{"duplicate issuer", base + "&iss=https%3A%2F%2Faccounts.google.com", http.StatusBadRequest},
		{"duplicate metadata", base + "&authuser=0&authuser=1", http.StatusBadRequest},
		{"duplicate extension", base + "&extension=1&%65xtension=2", http.StatusBadRequest},
		{"mixed code and error", base + "&error=access_denied", http.StatusBadRequest},
		{"empty code", strings.Replace(base, "code=synthetic-code", "code=", 1), http.StatusBadRequest},
		{"missing state", "iss=https%3A%2F%2Faccounts.google.com&code=synthetic-code", http.StatusBadRequest},
		{"malformed escape", base + "&extension=%GG", http.StatusBadRequest},
		{"oversized extension", base + "&extension=" + strings.Repeat("x", 8192), http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/v1/saas/callback/google-synthetic?"+tc.query, nil)
			r.SetPathValue("provider_id", "google-synthetic")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.AccountConnectionOAuth2Callback(w, r)
			// Valid metadata reaches rejection of the unissued state, without HTTP exchange.
			if w.Code != tc.want {
				t.Fatalf("callback status=%d want=%d", w.Code, tc.want)
			}
		})
	}
	var denialBody string
	for _, query := range []string{
		"state=synthetic-unissued-state&iss=https%3A%2F%2Faccounts.google.com&error=access_denied",
		"state=other-unissued-state&iss=https%3A%2F%2Faccounts.google.com&error=access_denied&error_description=%3Cscript%3E&error_uri=https%3A%2F%2Fevil.example",
		"state=synthetic-unissued-state&iss=https%3A%2F%2Fevil.example&error=access_denied",
	} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/saas/callback/google-synthetic?"+query, nil)
		r.SetPathValue("provider_id", "google-synthetic")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.AccountConnectionOAuth2Callback(w, r)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "script") || strings.Contains(w.Body.String(), "evil.example") {
			t.Fatal("denial was not generic")
		}
		if denialBody != "" && denialBody != w.Body.String() {
			t.Fatal("denial leaked binding details")
		}
		denialBody = w.Body.String()
	}
}

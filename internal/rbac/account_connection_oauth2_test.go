package rbac

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

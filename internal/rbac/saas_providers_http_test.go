package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
)

func TestSaaSProvidersAdminCatalogAndDefensiveCopy(t *testing.T) {
	h, store, adminCookie, _ := membershipHTTPFixture(t)
	scopes := []string{"read:user"}
	providers := []SaaSProviderInfo{{ID: "z", Kind: "github", CallbackURI: "https://app/z", Scopes: scopes}, {ID: "a", Kind: "oauth2", CallbackURI: "https://app/a", Scopes: []string{"openid"}}}
	if err := h.BindSaaSProviders(providers); err != nil {
		t.Fatal(err)
	}
	providers[0].ID, providers[0].Scopes[0] = "mutated", "mutated"
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/saas/providers", nil)
	r.AddCookie(adminCookie)
	w := httptest.NewRecorder()
	h.SaaSProviders(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got []SaaSProviderInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got) != 2 || got[0].ID != "a" || got[1].ID != "z" || got[1].Scopes[0] != "read:user" {
		t.Fatalf("catalog=%#v err=%v", got, err)
	}
	for _, setup := range []func(*http.Request){func(r *http.Request) { r.URL.RawQuery = "x=1" }, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/saas/providers", nil)
		r.AddCookie(adminCookie)
		setup(r)
		w := httptest.NewRecorder()
		h.SaaSProviders(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("boundary status=%d", w.Code)
		}
	}
	for _, invalid := range []SaaSProviderInfo{{ID: "a", Kind: "oauth2", CallbackURI: "https://x"}, {ID: " ", Kind: "oauth2", CallbackURI: "https://x"}} {
		if err := h.BindSaaSProviders([]SaaSProviderInfo{{ID: "a", Kind: "oauth2", CallbackURI: "https://x"}, invalid}); err == nil {
			t.Fatal("invalid catalog accepted")
		}
	}
	_ = store
}

func TestSaaSProvidersRequiresFullAdminBrowserSession(t *testing.T) {
	h, store, adminCookie, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSProviders([]SaaSProviderInfo{{ID: "github", Kind: "github", CallbackURI: "https://app/callback"}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	issued, err := h.browser.CreateSession(ctx, "member", "pwd", time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	userCookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(*http.Request){"anonymous": func(*http.Request) {}, "user": func(r *http.Request) { r.AddCookie(userCookie) }} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/v1/saas/providers", nil)
			setup(r)
			w := httptest.NewRecorder()
			h.SaaSProviders(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "saas-test", Access: []apikey.Access{{Group: "Roles", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, authorization := range map[string]string{"valid API key": "API-Key " + token, "bearer": "Bearer valid", "malformed API key": "API-Key malformed"} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/v1/saas/providers", nil)
			r.Header.Set("Authorization", authorization)
			r.AddCookie(adminCookie)
			w := httptest.NewRecorder()
			h.SaaSProviders(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}

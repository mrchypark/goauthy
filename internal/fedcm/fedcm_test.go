package fedcm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestAssertionBindsCurrentAccountAndRequest(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: private.Public(), KeyID: "test-key", Algorithm: string(jose.EdDSA), Use: "sig"}}
	h, err := NewHandler(Config{
		Issuer: "https://idp.example.test", Enabled: true, ClientID: "client-1", ClientOrigin: "https://rp.example.test",
		ResolveCurrent: func(context.Context, *http.Request) (Account, error) {
			return Account{ID: "acct1", Name: "Ada", Email: "ada@example.test"}, nil
		}, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"account_id": {"acct1"}, "client_id": {"client-1"}, "nonce": {"nonce-1"}, "disclosure_text_shown": {"true"}}
	r := httptest.NewRequest(http.MethodPost, AssertionPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://rp.example.test")
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache-control=%q body=%s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Token == "" {
		t.Fatalf("response=%s err=%v", rec.Body.String(), err)
	}
	claims, err := oidc.VerifyIDToken(response.Token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, "https://idp.example.test", "client-1", now)
	if err != nil || claims.Subject != "acct1" || claims.Nonce != "nonce-1" {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	form.Set("client_id", "client-2")
	r = httptest.NewRequest(http.MethodPost, AssertionPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://rp.example.test")
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("arbitrary audience status=%d body=%s", rec.Code, rec.Body.String())
	}
	form.Set("client_id", "client-1")
	r = httptest.NewRequest(http.MethodPost, AssertionPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://rp.example.test")
	r.Header.Add("Sec-Fetch-Dest", "webidentity")
	r.Header.Add("Sec-Fetch-Dest", "webidentity")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("duplicate fetch-dest status=%d", rec.Code)
	}
	r = httptest.NewRequest(http.MethodPost, AssertionPath, strings.NewReader(form.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://rp.example.test")
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate content-type status=%d", rec.Code)
	}
}

func TestBindingModesAndStrictHeaders(t *testing.T) {
	base := Config{Issuer: "https://idp.example.test", Enabled: true}
	for name, cfg := range map[string]Config{
		"missing pair": {Issuer: base.Issuer, Enabled: true, ClientID: "client-1"},
		"half pair":    {Issuer: base.Issuer, Enabled: true, ClientOrigin: "https://rp.example.test"},
		"ambiguous":    {Issuer: base.Issuer, Enabled: true, ClientID: "client-1", ClientOrigin: "https://rp.example.test", ClientOrigins: map[string]string{"client-1": "https://rp.example.test"}},
		"two dynamic":  {Issuer: base.Issuer, Enabled: true, ClientOrigins: map[string]string{"client-1": "https://rp.example.test"}, ResolveClientOrigin: func(context.Context, string) (string, error) { return "https://rp.example.test", nil }},
	} {
		if _, err := NewHandler(cfg); err == nil {
			t.Fatalf("%s: expected constructor failure", name)
		}
	}
	h, err := NewHandler(Config{Issuer: base.Issuer, Enabled: true, ClientOrigins: map[string]string{"client-1": "https://rp.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, ClientMetadataPath+"?client_id=client-1", nil)
	r.Header.Set("Origin", "https://other.example.test")
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("wrong origin status=%d cors=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
	r = httptest.NewRequest(http.MethodGet, ClientMetadataPath+"?client_id=client-1", nil)
	r.Header.Add("Origin", "https://rp.example.test")
	r.Header.Add("Origin", "https://rp.example.test")
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("duplicate origin status=%d", rec.Code)
	}
}

func TestConstructorRequiresHTTPSOriginsAndRelativeLoginPath(t *testing.T) {
	base := Config{Issuer: "https://idp.example.test", Enabled: true, ClientID: "client-1", ClientOrigin: "https://rp.example.test"}
	for name, cfg := range map[string]Config{
		"http origin":             {Issuer: base.Issuer, Enabled: true, ClientID: base.ClientID, ClientOrigin: "http://rp.example.test"},
		"absolute login":          {Issuer: base.Issuer, Enabled: true, ClientID: base.ClientID, ClientOrigin: base.ClientOrigin, LoginURL: "https://idp.example.test/auth/login"},
		"protocol relative login": {Issuer: base.Issuer, Enabled: true, ClientID: base.ClientID, ClientOrigin: base.ClientOrigin, LoginURL: "//idp.example.test/auth/login"},
		"query login":             {Issuer: base.Issuer, Enabled: true, ClientID: base.ClientID, ClientOrigin: base.ClientOrigin, LoginURL: "/auth/login?next=x"},
		"noncanonical login":      {Issuer: base.Issuer, Enabled: true, ClientID: base.ClientID, ClientOrigin: base.ClientOrigin, LoginURL: "/auth/../login"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHandler(cfg); err == nil {
				t.Fatal("unsafe FedCM configuration accepted")
			}
		})
	}
}

func TestAccountsRejectsRPIdentifiersAndOrigin(t *testing.T) {
	h, err := NewHandler(Config{Issuer: "https://idp.example.test", Enabled: true, ClientID: "client-1", ClientOrigin: "https://rp.example.test", ResolveAccounts: func(context.Context, *http.Request) ([]Account, error) {
		return []Account{{ID: "acct1", Name: "Ada", Email: "ada@example.test"}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, AccountsPath+"?client_id=rp", nil)
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, AccountsPath, nil)
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("status=%d cors=%q body=%s", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"), rec.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, AccountsPath, nil)
	r.Header.Set("Sec-Fetch-Dest", "webidentity")
	r.Header.Add("Origin", "https://rp.example.test")
	r.Header.Add("Origin", "https://rp.example.test")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("duplicate origin on uncredentialed endpoint status=%d", rec.Code)
	}
}

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestJWKSHandlerReturnsOnlyPublicKeyAndSupportsETag(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	key, err := EnsureSigningKey(context.Background(), db, keyring, issuer, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}

	handler := JWKSHandler(db, keyring, issuer)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oidc/jwks.json", nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("status=%d content-type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(response.Body.Bytes(), &keySet); err != nil {
		t.Fatal(err)
	}
	if len(keySet.Keys) != 1 || !keySet.Keys[0].IsPublic() || keySet.Keys[0].KeyID != key.PublicJWK.KeyID {
		t.Fatalf("unexpected JWKS: %#v", keySet.Keys)
	}
	etag := response.Header().Get("ETag")
	if etag == "" {
		t.Fatal("JWKS response has no ETag")
	}

	request := httptest.NewRequest(http.MethodGet, "/oidc/jwks.json", nil)
	request.Header.Set("If-None-Match", etag)
	notModified := httptest.NewRecorder()
	handler.ServeHTTP(notModified, request)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("conditional status=%d body=%q", notModified.Code, notModified.Body.String())
	}

	for _, value := range []string{`"other", ` + etag, "*", "W/" + etag} {
		request := httptest.NewRequest(http.MethodGet, "/oidc/jwks.json", nil)
		request.Header.Set("If-None-Match", value)
		conditional := httptest.NewRecorder()
		handler.ServeHTTP(conditional, request)
		if conditional.Code != http.StatusNotModified {
			t.Errorf("If-None-Match %q: status=%d", value, conditional.Code)
		}
	}

	now := time.Unix(1_900_000_000, 0).UTC()
	prepared, err := PrepareSigningKey(context.Background(), db, keyring, issuer, now)
	if err != nil || !prepared.Prepared {
		t.Fatalf("prepare signing key: result=%#v err=%v", prepared, err)
	}
	rotation, err := ActivatePreparedSigningKey(context.Background(), db, keyring, issuer, key.PublicJWK.KeyID, prepared.PendingKID, prepared.ActivatesAfter.Add(MinimumSigningKeyRetirement), prepared.ActivatesAfter)
	if err != nil || !rotation.Activated {
		t.Fatalf("activate signing key: result=%#v err=%v", rotation, err)
	}
	rotated := httptest.NewRecorder()
	handler.ServeHTTP(rotated, httptest.NewRequest(http.MethodGet, "/oidc/jwks.json", nil))
	if err := json.Unmarshal(rotated.Body.Bytes(), &keySet); err != nil {
		t.Fatal(err)
	}
	if len(keySet.Keys) != 2 || keySet.Keys[0].KeyID != rotation.Active.PublicJWK.KeyID || keySet.Keys[1].KeyID != key.PublicJWK.KeyID {
		t.Fatalf("rotated JWKS: %#v", keySet.Keys)
	}
}

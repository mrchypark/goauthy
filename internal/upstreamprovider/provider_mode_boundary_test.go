package upstreamprovider

import (
	"errors"
	"reflect"
	"testing"
)

// --- Fixture ---

func boundaryFixture(t *testing.T) *mutationFixture {
	t.Helper()
	return newMutationFixture(t)
}

// Fixed 24-char ASCII IDs for each isolated test (rauthy new_store_id format).
const (
	boundaryCreateID    = "AbCdEfGhIjKlMnOpQrStUvWx"
	boundaryCrossO2OID  = "AbCdEfGhIjKlMnOpQrStUvWx"
	boundaryCrossOID2O  = "AbCdEfGhIjKlMnOpQrStUvWx"
	boundarySameOAuthID = "AbCdEfGhIjKlMnOpQrStUvWx"
	boundaryCustOIDID   = "AbCdEfGhIjKlMnOpQrStUvWx"
)

func boundaryOAuthUserInfoRequest(name, secret string) ProviderRequest {
	return ProviderRequest{
		Name:                  name,
		Typ:                   AuthProviderTypeOAuthUserInfo,
		Enabled:               true,
		Issuer:                "https://example.test",
		AuthorizationEndpoint: "https://example.test/auth",
		TokenEndpoint:         "https://example.test/token",
		UserinfoEndpoint:      "https://example.test/userinfo",
		ClientID:              "cid-test",
		ClientSecret:          secretPtr(secret),
		Scope:                 "openid profile",
		UsePKCE:               true,
		ClientSecretBasic:     true,
		ClientSecretPost:      false,
	}
}

func boundaryOIDCRequest(name string) ProviderRequest {
	return ProviderRequest{
		Name:                  name,
		Typ:                   AuthProviderTypeOIDC,
		Enabled:               true,
		Issuer:                "https://example.test",
		AuthorizationEndpoint: "https://example.test/auth",
		TokenEndpoint:         "https://example.test/token",
		UserinfoEndpoint:      "https://example.test/userinfo",
		ClientID:              "cid-test",
		Scope:                 "openid",
		UsePKCE:               true,
		ClientSecretBasic:     true,
		ClientSecretPost:      false,
	}
}

func boundaryCustomRequest(name string) ProviderRequest {
	return ProviderRequest{
		Name:                  name,
		Typ:                   AuthProviderTypeCustom,
		Enabled:               true,
		Issuer:                "https://example.test",
		AuthorizationEndpoint: "https://example.test/auth",
		TokenEndpoint:         "https://example.test/token",
		UserinfoEndpoint:      "https://example.test/userinfo",
		ClientID:              "cid-test",
		Scope:                 "openid",
		UsePKCE:               true,
		ClientSecretBasic:     true,
		ClientSecretPost:      false,
	}
}

func secretPtr(s string) *string { return &s }

// --- Test: CreateAuthorized oauth_userinfo with PKCE, no JWKS, encrypted secret ---

func TestProviderModeBoundaryCreateOAuthUserInfo(t *testing.T) {
	f := boundaryFixture(t)
	secret := "oauth-ui-secret"
	if len(boundaryCreateID) != 24 {
		t.Fatalf("len(boundaryCreateID)=%d, want 24", len(boundaryCreateID))
	}
	doc, err := f.store.CreateAuthorized(f.ctx,
		boundaryCreateID, f.newRequestID("req"),
		boundaryOAuthUserInfoRequest("OAuth UserInfo Provider", secret),
		f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	if doc.ID != boundaryCreateID {
		t.Fatalf("ID = %q, want %q", doc.ID, boundaryCreateID)
	}
	if doc.Typ != AuthProviderTypeOAuthUserInfo {
		t.Fatalf("Typ = %q, want %q", doc.Typ, AuthProviderTypeOAuthUserInfo)
	}
	if doc.Secret == nil {
		t.Fatal("expected non-nil encrypted secret")
	}
	if string(doc.Secret) == secret {
		t.Fatal("secret stored as plaintext")
	}

	// GetRuntime returns the provider with correct kind and a non-empty version.
	gotDoc, gotVer, err := f.store.GetRuntime(f.ctx, boundaryCreateID)
	if err != nil {
		t.Fatalf("GetRuntime: %v", err)
	}
	if gotDoc.Typ != AuthProviderTypeOAuthUserInfo {
		t.Fatalf("GetRuntime Typ = %q, want %q", gotDoc.Typ, AuthProviderTypeOAuthUserInfo)
	}
	if gotVer == "" {
		t.Fatal("GetRuntime version is empty")
	}

	// RuntimeConfig: valid source, correct kind, PKCE true, no JWKS, secret decrypted.
	cfg, returnedSecret, err := f.store.RuntimeConfig(f.ctx, boundaryCreateID)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if cfg.Kind != ProviderKindOAuthUserInfo {
		t.Fatalf("RuntimeConfig Kind = %q, want %q", cfg.Kind, ProviderKindOAuthUserInfo)
	}
	if cfg.RuntimeVersion == "" {
		t.Fatal("RuntimeConfig RuntimeVersion is empty")
	}
	if cfg.UserInfoEndpoint != "https://example.test/userinfo" {
		t.Fatalf("RuntimeConfig UserInfoEndpoint = %q", cfg.UserInfoEndpoint)
	}
	if cfg.Protocol.UsePKCE == nil || !*cfg.Protocol.UsePKCE {
		t.Fatal("UsePKCE should be true")
	}
	if cfg.JWKSURI != "" {
		t.Fatalf("JWKSURI should be empty, got %q", cfg.JWKSURI)
	}
	if returnedSecret == nil || *returnedSecret != secret {
		t.Fatalf("RuntimeConfig secret = %v, want %q", returnedSecret, secret)
	}
}

// --- Test: Cross-mode transitions rejected by v97 trigger (both directions) ---
// Cross-mode request changes name+secret so rollback is verifiable via full
// ProviderDocument equality (reflect.DeepEqual), not just typ/secret/version.

func TestProviderModeBoundaryCrossOAuthToOIDC(t *testing.T) {
	f := boundaryFixture(t)
	secret := "cross-oauth-secret"
	if len(boundaryCrossO2OID) != 24 {
		t.Fatalf("len(boundaryCrossO2OID)=%d, want 24", len(boundaryCrossO2OID))
	}
	_, err := f.store.CreateAuthorized(f.ctx,
		boundaryCrossO2OID, f.newRequestID("req"),
		boundaryOAuthUserInfoRequest("Cross OAuth", secret),
		f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	preDoc, err := f.store.Get(f.ctx, boundaryCrossO2OID)
	if err != nil {
		t.Fatal(err)
	}
	v1 := readRuntimeVersion(t, f.db, boundaryCrossO2OID)

	// Attempt oauth_userinfo -> oidc with name+secret change: v97 trigger aborts.
	_, err = f.store.UpdateAuthorized(f.ctx, boundaryCrossO2OID, f.newRequestID("upd"),
		boundaryOIDCRequest("Cross OAuth Updated"),
		f.keys, f.principal)
	if errors.Is(err, nil) {
		t.Fatal("oauth_userinfo->oidc should fail, got nil error")
	}

	// Full document equality preserved (transaction rolled back entirely).
	afterDoc, err := f.store.Get(f.ctx, boundaryCrossO2OID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(preDoc, afterDoc) {
		t.Fatalf("document changed after rejected transition:\n  pre:  %+v\n  post: %+v", preDoc, afterDoc)
	}
	v2 := readRuntimeVersion(t, f.db, boundaryCrossO2OID)
	if v2 != v1 {
		t.Fatalf("version changed after rejected transition: %q -> %q", v1, v2)
	}
}

func TestProviderModeBoundaryCrossOIDCToOAuthUserInfo(t *testing.T) {
	f := boundaryFixture(t)
	if len(boundaryCrossOID2O) != 24 {
		t.Fatalf("len(boundaryCrossOID2O)=%d, want 24", len(boundaryCrossOID2O))
	}
	_, err := f.store.CreateAuthorized(f.ctx,
		boundaryCrossOID2O, f.newRequestID("req"),
		boundaryOIDCRequest("Cross OIDC"),
		f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	preDoc, err := f.store.Get(f.ctx, boundaryCrossOID2O)
	if err != nil {
		t.Fatal(err)
	}
	v1 := readRuntimeVersion(t, f.db, boundaryCrossOID2O)

	// Attempt oidc -> oauth_userinfo with name+secret change: v97 trigger aborts.
	_, err = f.store.UpdateAuthorized(f.ctx, boundaryCrossOID2O, f.newRequestID("upd"),
		boundaryOAuthUserInfoRequest("Cross OIDC Updated", "new-secret"),
		f.keys, f.principal)
	if errors.Is(err, nil) {
		t.Fatal("oidc->oauth_userinfo should fail, got nil error")
	}

	afterDoc, err := f.store.Get(f.ctx, boundaryCrossOID2O)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(preDoc, afterDoc) {
		t.Fatalf("document changed after rejected transition:\n  pre:  %+v\n  post: %+v", preDoc, afterDoc)
	}
	v2 := readRuntimeVersion(t, f.db, boundaryCrossOID2O)
	if v2 != v1 {
		t.Fatalf("version changed after rejected transition: %q -> %q", v1, v2)
	}
}

// --- Test: Same-mode oauth_userinfo update allowed, rotates version ---

func TestProviderModeBoundarySameModeOAuthUserInfoAllowed(t *testing.T) {
	f := boundaryFixture(t)
	origSecret := "orig-secret"
	if len(boundarySameOAuthID) != 24 {
		t.Fatalf("len(boundarySameOAuthID)=%d, want 24", len(boundarySameOAuthID))
	}
	_, err := f.store.CreateAuthorized(f.ctx,
		boundarySameOAuthID, f.newRequestID("req"),
		boundaryOAuthUserInfoRequest("Same Mode OAuth", origSecret),
		f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	v1 := readRuntimeVersion(t, f.db, boundarySameOAuthID)

	// Same-type update: change name and secret.
	newSecret := "new-secret"
	_, err = f.store.UpdateAuthorized(f.ctx, boundarySameOAuthID, f.newRequestID("upd"),
		boundaryOAuthUserInfoRequest("Same Mode OAuth Updated", newSecret),
		f.keys, f.principal)
	if err != nil {
		t.Fatalf("UpdateAuthorized: %v", err)
	}

	// Version must rotate on successful update.
	v2 := readRuntimeVersion(t, f.db, boundarySameOAuthID)
	if v2 == v1 {
		t.Fatalf("version did not change: %q", v2)
	}

	// Name updated.
	afterDoc, err := f.store.Get(f.ctx, boundarySameOAuthID)
	if err != nil {
		t.Fatal(err)
	}
	if afterDoc.Name != "Same Mode OAuth Updated" {
		t.Fatalf("name = %q, want updated name", afterDoc.Name)
	}

	// Secret updated (encrypted ciphertext, not plaintext).
	if afterDoc.Secret == nil {
		t.Fatal("expected non-nil secret after update")
	}
	purpose := ProviderSecretPurpose(boundarySameOAuthID)
	cleartext, err := f.keyring.OpenEnvelope(purpose, afterDoc.Secret)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if string(cleartext) != newSecret {
		t.Fatalf("cleartext = %q, want %q", cleartext, newSecret)
	}

	// Type unchanged.
	if afterDoc.Typ != AuthProviderTypeOAuthUserInfo {
		t.Fatalf("typ = %q, want %q", afterDoc.Typ, AuthProviderTypeOAuthUserInfo)
	}

	// RuntimeConfig reflects the update.
	cfg, _, err := f.store.RuntimeConfig(f.ctx, boundarySameOAuthID)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if cfg.Kind != ProviderKindOAuthUserInfo {
		t.Fatalf("RuntimeConfig Kind = %q, want %q", cfg.Kind, ProviderKindOAuthUserInfo)
	}
}

// --- Test: custom->oidc allowed (neither is oauth_userinfo, v97 trigger not violated) ---

func TestProviderModeBoundaryCustomToOIDCAllowed(t *testing.T) {
	f := boundaryFixture(t)
	if len(boundaryCustOIDID) != 24 {
		t.Fatalf("len(boundaryCustOIDID)=%d, want 24", len(boundaryCustOIDID))
	}
	_, err := f.store.CreateAuthorized(f.ctx,
		boundaryCustOIDID, f.newRequestID("req"),
		boundaryCustomRequest("Custom Provider"),
		f.keys, f.principal)
	if err != nil {
		t.Fatalf("CreateAuthorized: %v", err)
	}
	v1 := readRuntimeVersion(t, f.db, boundaryCustOIDID)

	// custom -> oidc: neither old nor new is oauth_userinfo, so allowed.
	_, err = f.store.UpdateAuthorized(f.ctx, boundaryCustOIDID, f.newRequestID("upd"),
		boundaryOIDCRequest("Custom Provider Updated"),
		f.keys, f.principal)
	if err != nil {
		t.Fatalf("custom->oidc should be allowed: %v", err)
	}
	v2 := readRuntimeVersion(t, f.db, boundaryCustOIDID)
	if v2 == v1 {
		t.Fatalf("version did not change: %q", v2)
	}
	afterDoc, err := f.store.Get(f.ctx, boundaryCustOIDID)
	if err != nil {
		t.Fatal(err)
	}
	if afterDoc.Typ != AuthProviderTypeOIDC {
		t.Fatalf("typ = %q, want %q", afterDoc.Typ, AuthProviderTypeOIDC)
	}
}

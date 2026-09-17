package upstreamprovider

import (
	"testing"
	"time"
)

// TestRuntimePolicyRetainsAllFields proves that CreateAuthorized followed
// by RuntimeConfig preserves all 6 policy fields and the source version.
func TestRuntimePolicyRetainsAllFields(t *testing.T) {
	f := runtimeFixture(t)
	id := "AbCdEfGhIjKlMnOpQrStUvWx"
	if len(id) != 24 {
		t.Fatalf("provider ID must be 24 chars, got %d", len(id))
	}

	path := ".claims.admin"
	val := "true"
	mfaPath := ".claims.mfa"
	mfaVal := "totp"

	req := validProviderMutationRequest()
	req.AutoOnboarding = true
	req.AutoLink = true
	req.AdminClaimPath = &path
	req.AdminClaimValue = &val
	req.MFAClaimPath = &mfaPath
	req.MFAClaimValue = &mfaVal

	_, err := f.store.CreateAuthorized(f.ctx, id, f.newRequestID("seed-pol"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoOnboarding {
		t.Error("AutoOnboarding = false, want true")
	}
	if !cfg.AutoLink {
		t.Error("AutoLink = false, want true")
	}
	if cfg.AdminClaimPath == nil || *cfg.AdminClaimPath != path {
		t.Errorf("AdminClaimPath = %v, want %q", cfg.AdminClaimPath, path)
	}
	if cfg.AdminClaimValue == nil || *cfg.AdminClaimValue != val {
		t.Errorf("AdminClaimValue = %v, want %q", cfg.AdminClaimValue, val)
	}
	if cfg.MFAClaimPath == nil || *cfg.MFAClaimPath != mfaPath {
		t.Errorf("MFAClaimPath = %v, want %q", cfg.MFAClaimPath, mfaPath)
	}
	if cfg.MFAClaimValue == nil || *cfg.MFAClaimValue != mfaVal {
		t.Errorf("MFAClaimValue = %v, want %q", cfg.MFAClaimValue, mfaVal)
	}
	if cfg.RuntimeVersion == "" {
		t.Error("RuntimeVersion is empty")
	}
	if cfg.ProviderSource != "registry" {
		t.Errorf("ProviderSource = %q, want registry", cfg.ProviderSource)
	}
}

// TestRuntimePolicyNilFieldsWhenAbsent proves that nil pointer policy
// fields in the document produce nil pointers in the Config.
func TestRuntimePolicyNilFieldsWhenAbsent(t *testing.T) {
	f := runtimeFixture(t)
	id := "AbCdEfGhIjKlMnOpQrStUvWx"
	if len(id) != 24 {
		t.Fatalf("provider ID must be 24 chars, got %d", len(id))
	}

	req := validProviderMutationRequest()
	req.ClientSecret = nil
	if _, err := f.store.CreateAuthorized(f.ctx, id, f.newRequestID("nil-pol"), req, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := f.store.RuntimeConfig(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoOnboarding != req.AutoOnboarding {
		t.Errorf("AutoOnboarding = %v, want %v (from request)", cfg.AutoOnboarding, req.AutoOnboarding)
	}
	if cfg.AutoLink != req.AutoLink {
		t.Errorf("AutoLink = %v, want %v (from request)", cfg.AutoLink, req.AutoLink)
	}
	if cfg.AdminClaimPath != nil {
		t.Errorf("AdminClaimPath = %v, want nil", *cfg.AdminClaimPath)
	}
	if cfg.AdminClaimValue != nil {
		t.Errorf("AdminClaimValue = %v, want nil", *cfg.AdminClaimValue)
	}
	if cfg.MFAClaimPath != nil {
		t.Errorf("MFAClaimPath = %v, want nil", *cfg.MFAClaimPath)
	}
	if cfg.MFAClaimValue != nil {
		t.Errorf("MFAClaimValue = %v, want nil", *cfg.MFAClaimValue)
	}
}

// TestRuntimePolicyHandlerCloneImmune proves that NewHandler deep-copies
// policy pointer fields so the caller can safely mutate after construction.
func TestRuntimePolicyHandlerCloneImmune(t *testing.T) {
	configs := map[string]Config{
		"google": {
			Issuer:                "https://issuer.example.com",
			AuthorizationEndpoint: "https://issuer.example.com/auth",
			TokenEndpoint:         "https://issuer.example.com/token",
			ClientID:              "test-client",
			Scopes:                []string{"openid"},
			Protocol: ProviderProtocol{
				UsePKCE: boolPtr(true),
			},
			AdminClaimPath:  strPtr(".claims.admin"),
			AdminClaimValue: strPtr("true"),
			MFAClaimPath:    strPtr(".claims.mfa"),
			MFAClaimValue:   strPtr("totp"),
		},
	}
	allowed := map[string]bool{"https://app.example.com/callback": true}
	store := newTestStore()
	verifier := &deterministicVerifier{
		claims: &IDTokenClaims{
			Issuer: "https://issuer.example.com", Subject: "s",
			Audience:  []string{"test-client"},
			ExpiresAt: fixedNow.Add(time.Hour).Unix(),
			IssuedAt:  fixedNow.Add(-time.Minute).Unix(),
		},
		store: store,
	}
	h, err := NewHandler(configs, store, &fakeTokenExchanger{idToken: "tok"}, verifier,
		newCryptoProvider(newFixedRandom(make([]byte, 256))), allowed)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate pointees through the original map entry. A shallow copy would
	// leak these mutations into the handler's internal config.
	*configs["google"].AdminClaimPath = "CHANGED"
	*configs["google"].AdminClaimValue = "CHANGED"
	*configs["google"].MFAClaimPath = "CHANGED"
	*configs["google"].MFAClaimValue = "CHANGED"
	configs["google"].Scopes[0] = "mutated"
	*configs["google"].Protocol.UsePKCE = false

	// Handler internal config must be unaffected.
	hcfg := h.configs["google"]
	if hcfg.AdminClaimPath == nil || *hcfg.AdminClaimPath != ".claims.admin" {
		t.Errorf("AdminClaimPath leaked mutation: %v", hcfg.AdminClaimPath)
	}
	if hcfg.AdminClaimValue == nil || *hcfg.AdminClaimValue != "true" {
		t.Errorf("AdminClaimValue leaked mutation: %v", hcfg.AdminClaimValue)
	}
	if hcfg.MFAClaimPath == nil || *hcfg.MFAClaimPath != ".claims.mfa" {
		t.Errorf("MFAClaimPath leaked mutation: %v", hcfg.MFAClaimPath)
	}
	if hcfg.MFAClaimValue == nil || *hcfg.MFAClaimValue != "totp" {
		t.Errorf("MFAClaimValue leaked mutation: %v", hcfg.MFAClaimValue)
	}
	if len(hcfg.Scopes) != 1 || hcfg.Scopes[0] != "openid" {
		t.Errorf("Scopes leaked mutation: %v", hcfg.Scopes)
	}
	if hcfg.Protocol.UsePKCE == nil || !*hcfg.Protocol.UsePKCE {
		t.Errorf("Protocol.UsePKCE leaked mutation: %v", hcfg.Protocol.UsePKCE)
	}
}

// TestRuntimePolicyExchangerCloneImmune proves that
// NewOAuth2TokenExchanger deep-copies policy pointer fields.
func TestRuntimePolicyExchangerCloneImmune(t *testing.T) {
	configs := map[string]Config{
		"google": {
			Issuer:                "https://issuer.example.com",
			AuthorizationEndpoint: "https://issuer.example.com/auth",
			TokenEndpoint:         "https://issuer.example.com/token",
			ClientID:              "test-client",
			Scopes:                []string{"openid"},
			Protocol: ProviderProtocol{
				UsePKCE:           boolPtr(true),
				ClientSecretBasic: boolPtr(true),
			},
			AdminClaimPath:  strPtr(".claims.admin"),
			AdminClaimValue: strPtr("true"),
			MFAClaimPath:    strPtr(".claims.mfa"),
			MFAClaimValue:   strPtr("totp"),
		},
	}
	secrets := map[string]string{"google": "s3cret"}

	ex, err := NewOAuth2TokenExchanger(configs, secrets, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate pointees through the original map entry.
	*configs["google"].AdminClaimPath = "CHANGED"
	*configs["google"].AdminClaimValue = "CHANGED"
	*configs["google"].MFAClaimPath = "CHANGED"
	*configs["google"].MFAClaimValue = "CHANGED"
	configs["google"].Scopes[0] = "mutated"
	*configs["google"].Protocol.UsePKCE = false

	// Exchanger internal config must be unaffected.
	ecfg := ex.configs["google"]
	if ecfg.AdminClaimPath == nil || *ecfg.AdminClaimPath != ".claims.admin" {
		t.Errorf("AdminClaimPath leaked mutation: %v", ecfg.AdminClaimPath)
	}
	if ecfg.AdminClaimValue == nil || *ecfg.AdminClaimValue != "true" {
		t.Errorf("AdminClaimValue leaked mutation: %v", ecfg.AdminClaimValue)
	}
	if ecfg.MFAClaimPath == nil || *ecfg.MFAClaimPath != ".claims.mfa" {
		t.Errorf("MFAClaimPath leaked mutation: %v", ecfg.MFAClaimPath)
	}
	if ecfg.MFAClaimValue == nil || *ecfg.MFAClaimValue != "totp" {
		t.Errorf("MFAClaimValue leaked mutation: %v", ecfg.MFAClaimValue)
	}
	if len(ecfg.Scopes) != 1 || ecfg.Scopes[0] != "openid" {
		t.Errorf("Scopes leaked mutation: %v", ecfg.Scopes)
	}
	if ecfg.Protocol.UsePKCE == nil || !*ecfg.Protocol.UsePKCE {
		t.Errorf("Protocol.UsePKCE leaked mutation: %v", ecfg.Protocol.UsePKCE)
	}
}

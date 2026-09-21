package upstreamprovider

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validProviderRequest() ProviderRequest {
	jwks := "https://issuer.example.test/keys"
	secret := "secret-value"
	adminPath := "roles/admin"
	adminValue := "yes"
	return ProviderRequest{
		Name: "Example Provider", Typ: AuthProviderTypeOIDC, Enabled: true,
		Issuer: "https://issuer.example.test", AuthorizationEndpoint: "https://issuer.example.test/authorize",
		TokenEndpoint: "https://issuer.example.test/token", UserinfoEndpoint: "https://issuer.example.test/userinfo",
		JWKS: &jwks, UsePKCE: true, ClientSecretBasic: true, ClientSecretPost: false,
		AutoOnboarding: true, AutoLink: false, ClientID: "client-id", ClientSecret: &secret,
		Scope: "openid  profile email", AdminClaimPath: &adminPath, AdminClaimValue: &adminValue,
	}
}

func TestProviderRequestValidationAndNormalization(t *testing.T) {
	t.Parallel()
	req := validProviderRequest()
	if err := req.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	got := req.Normalize()
	if got.Scope != "openid+profile+email" {
		t.Fatalf("normalized scope = %q", got.Scope)
	}
	if req.Scope != "openid  profile email" {
		t.Fatalf("Normalize mutated input: %q", req.Scope)
	}

	minimal := validProviderRequest()
	minimal.JWKS, minimal.ClientSecret = nil, nil
	minimal.AdminClaimPath, minimal.AdminClaimValue = nil, nil
	minimal.MFAClaimPath, minimal.MFAClaimValue = nil, nil
	minimal.Scope = ""
	if err := minimal.Validate(); err != nil {
		t.Fatalf("minimal request rejected: %v", err)
	}
	if normalized := minimal.Normalize(); normalized.Scope != "" {
		t.Fatalf("empty scope normalized to %q", normalized.Scope)
	}
}

func TestProviderRequestAcceptsPinnedUnicodeWhitespace(t *testing.T) {
	t.Parallel()
	request := validProviderRequest()
	request.Name = "Example\u00a0Provider"
	request.Scope = "openid\u2003profile"
	if err := request.Validate(); err != nil {
		t.Fatalf("Unicode whitespace rejected: %v", err)
	}
	// AuthProvider::cleanup_scope uses split(' '), not split_whitespace:
	// Unicode whitespace is valid content but does not become a '+' separator.
	if got := request.Normalize().Scope; got != "openid\u2003profile" {
		t.Fatalf("Unicode whitespace normalization = %q", got)
	}
	request.Scope = " openid\u00a0profile "
	if got := request.Normalize().Scope; got != "openid\u00a0profile" {
		t.Fatalf("trimmed Unicode whitespace normalization = %q", got)
	}
}

func TestProviderRequestJSONRequiredAndOptionalFields(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(validProviderRequest())
	if err != nil {
		t.Fatal(err)
	}
	var got ProviderRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("round-tripped request rejected: %v", err)
	}

	var missing map[string]any
	if err := json.Unmarshal(data, &missing); err != nil {
		t.Fatal(err)
	}
	delete(missing, "enabled")
	missingData, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(missingData, &ProviderRequest{}); err == nil {
		t.Fatal("missing required enabled field accepted")
	}

	missing["enabled"] = nil
	nullData, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(nullData, &ProviderRequest{}); err == nil {
		t.Fatal("null required enabled field accepted")
	}

	missing["enabled"] = true
	missing["client_secret"] = nil
	optionalNull, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(optionalNull, &got); err != nil {
		t.Fatalf("null optional client_secret rejected: %v", err)
	}
}

func TestProviderRequestRejectsPinnedInvalidCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*ProviderRequest)
	}{
		{"name regex", func(r *ProviderRequest) { r.Name = "<bad>" }},
		{"uri regex", func(r *ProviderRequest) { r.Issuer = "https://issuer.example.test/invalid space" }},
		{"enum", func(r *ProviderRequest) { r.Typ = "unknown" }},
		{"scope regex", func(r *ProviderRequest) { r.Scope = "openid,profile" }},
		{"secret length", func(r *ProviderRequest) { v := strings.Repeat("x", 257); r.ClientSecret = &v }},
		{"optional claim regex", func(r *ProviderRequest) { v := "bad value"; r.MFAClaimValue = &v }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validProviderRequest()
			tc.edit(&req)
			if err := req.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestProviderLookupAndLinkedUserDocuments(t *testing.T) {
	t.Parallel()
	issuer := "issuer.example.test/tenant"
	request := ProviderLookupRequest{Issuer: &issuer}
	if err := request.ValidateForLookup(); err != nil {
		t.Fatalf("issuer lookup rejected: %v", err)
	}
	url, err := request.ResolveMetadataURL()
	if err != nil || url != "https://issuer.example.test/tenant/.well-known/openid-configuration" {
		t.Fatalf("issuer lookup URL = %q, err=%v", url, err)
	}

	metadata := "https://metadata.example.test/provider.json"
	request = ProviderLookupRequest{Issuer: &issuer, MetadataURL: &metadata}
	url, err = request.ResolveMetadataURL()
	if err != nil || url != metadata {
		t.Fatalf("metadata lookup URL = %q, err=%v", url, err)
	}
	if err := (ProviderLookupRequest{}).ValidateForLookup(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty lookup error = %v", err)
	}

	linked := ProviderLinkedUserResponse{ID: "user-1", Email: "user@example.test"}
	encoded, err := json.Marshal(linked)
	if err != nil || string(encoded) != `{"id":"user-1","email":"user@example.test"}` {
		t.Fatalf("linked user JSON = %s, err=%v", encoded, err)
	}
}

func TestProviderDocumentMapsAllPersistedFieldsAndResponseSecretPointer(t *testing.T) {
	t.Parallel()
	req := validProviderRequest()
	secretCiphertext := []byte("opaque-ciphertext")
	doc, err := req.Normalize().ToDocument("provider-1", secretCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if ProviderPersistedFieldCount != 21 {
		t.Fatalf("persisted field count = %d", ProviderPersistedFieldCount)
	}
	if doc.Scope != "openid+profile+email" || string(doc.Secret) != string(secretCiphertext) {
		t.Fatalf("document mapping scope=%q secret=%q", doc.Scope, doc.Secret)
	}
	secret := "admin-read-secret"
	response := doc.Response(&secret)
	if response.ClientSecret != &secret || response.Scope != doc.Scope || response.ID != doc.ID {
		t.Fatalf("response projection = %+v", response)
	}
	if doc.Response(nil).ClientSecret != nil {
		t.Fatal("nil response secret was populated")
	}
}

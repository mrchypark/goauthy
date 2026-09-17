package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryHandlerAdvertisesOnlyImplementedCapabilities(t *testing.T) {
	handler := DiscoveryHandler("https://id.example.com/", false)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

	const want = `{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/oidc/authorize","token_endpoint":"https://id.example.com/oidc/token","jwks_uri":"https://id.example.com/oidc/jwks.json","introspection_endpoint":"https://id.example.com/oidc/introspect","revocation_endpoint":"https://id.example.com/oidc/revoke","device_authorization_endpoint":"https://id.example.com/oidc/device","grant_types_supported":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:ietf:params:oauth:grant-type:token-exchange"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"dpop_signing_alg_values_supported":["ES256","ES384","ES512","RS256","RS384","RS512","PS256","PS384","PS512","EdDSA"]}`
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "public, max-age=300, must-revalidate" || response.Header().Get("ETag") == "" {
		t.Fatalf("headers=%v", response.Header())
	}
	for _, claim := range []string{"userinfo_endpoint", "id_token_signing_alg_values_supported", "registration_endpoint", "end_session_endpoint"} {
		if strings.Contains(response.Body.String(), claim) {
			t.Errorf("advertised unimplemented claim %q", claim)
		}
	}

	conditional := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	request.Header.Set("If-None-Match", response.Header().Get("ETag"))
	handler.ServeHTTP(conditional, request)
	if conditional.Code != http.StatusNotModified || conditional.Body.Len() != 0 {
		t.Fatalf("conditional status=%d body=%q", conditional.Code, conditional.Body.String())
	}
}

func TestDiscoveryHandlerRejectsInvalidIssuer(t *testing.T) {
	response := httptest.NewRecorder()
	DiscoveryHandler("https://id.example.com/?query", false).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestOpenIDDiscoveryAdvertisesImplementedClaims(t *testing.T) {
	response := httptest.NewRecorder()
	OpenIDDiscoveryHandler("https://id.example.com", false).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, field := range []string{`"userinfo_endpoint":"https://id.example.com/oidc/userinfo"`, `"end_session_endpoint":"https://id.example.com/oidc/logout"`, `"device_authorization_endpoint":"https://id.example.com/oidc/device"`, `"urn:ietf:params:oauth:grant-type:device_code"`, `"urn:ietf:params:oauth:grant-type:token-exchange"`, `"dpop_signing_alg_values_supported":["ES256","ES384","ES512","RS256","RS384","RS512","PS256","PS384","PS512","EdDSA"]`, `"backchannel_logout_supported":true`, `"backchannel_logout_session_supported":true`, `"scopes_supported":["openid","profile","email","address","phone","goauthy.read","offline_access","groups"]`, `"subject_types_supported":["public"]`, `"id_token_signing_alg_values_supported":["EdDSA"]`, `"sid"`, `"at_hash"`, `"roles"`, `"groups"`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Fatalf("missing %s: %s", field, response.Body.String())
		}
	}
	for _, unimplemented := range []string{"registration_endpoint"} {
		if strings.Contains(response.Body.String(), unimplemented) {
			t.Fatalf("advertised unimplemented field %q", unimplemented)
		}
	}
}

func TestDiscoveryUsesIssuerBasePath(t *testing.T) {
	response := httptest.NewRecorder()
	OpenIDDiscoveryHandler("https://id.example.com/tenant", false).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/tenant/.well-known/openid-configuration", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"issuer":"https://id.example.com/tenant"`) || !strings.Contains(response.Body.String(), `"authorization_endpoint":"https://id.example.com/tenant/oidc/authorize"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDiscoveryHandlersAdvertiseRegistrationOnlyWhenEnabled(t *testing.T) {
	for _, handler := range []http.Handler{
		DiscoveryHandler("https://id.example.com", true),
		OpenIDDiscoveryHandler("https://id.example.com", true),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/metadata", nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"registration_endpoint":"https://id.example.com/oidc/register"`) {
			t.Fatalf("DCR discovery response=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestDiscoveryHandlersAdvertiseCIMDOnlyWhenConfigured(t *testing.T) {
	for _, handler := range []http.Handler{
		DiscoveryHandlerWithOptions("https://id.example.com", DiscoveryOptions{ClientIDMetadataDocumentSupported: true}),
		OpenIDDiscoveryHandlerWithOptions("https://id.example.com", DiscoveryOptions{ClientIDMetadataDocumentSupported: true}),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/metadata", nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"client_id_metadata_document_supported":true`) {
			t.Fatalf("CIMD discovery response=%d body=%s", response.Code, response.Body.String())
		}
	}
	for _, handler := range []http.Handler{
		DiscoveryHandlerWithOptions("https://id.example.com", DiscoveryOptions{}),
		OpenIDDiscoveryHandlerWithOptions("https://id.example.com", DiscoveryOptions{}),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/metadata", nil))
		if strings.Contains(response.Body.String(), "client_id_metadata_document_supported") {
			t.Fatalf("advertised disabled CIMD: %s", response.Body.String())
		}
	}
}

func TestDiscoveryPasswordCapability(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		options := DiscoveryOptions{PasswordGrantEnabled: enabled}
		for _, handler := range []http.Handler{DiscoveryHandlerWithOptions("https://id.example.com", options), OpenIDDiscoveryHandlerWithOptions("https://id.example.com", options)} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
			if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"password"`) != enabled {
				t.Fatalf("password capability enabled=%t status=%d", enabled, w.Code)
			}
		}
	}
}

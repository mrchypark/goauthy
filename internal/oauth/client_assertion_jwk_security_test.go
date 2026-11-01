package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/ory/fosite"
)

// Keep malicious integers just above the parser's bound, never computationally
// expensive valid RSA keys. No request is authenticated with attacker keys.
func TestClientAssertionJWKRejectionPreservesAuthorization(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	verifier := strings.Repeat("v", 43)
	code := issueCode(t, server, verifier)
	issued := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueCode(t, server, verifier)}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	controlVerifier := strings.Repeat("c", 43)
	controlCode := issueCode(t, server, controlVerifier)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	originalClient := server.store.client
	base := &fosite.DefaultClient{ID: testClientID, Secret: append([]byte(nil), originalClient.GetHashedSecret()...), GrantTypes: originalClient.GetGrantTypes(), Scopes: originalClient.GetScopes()}
	server.store.client = &fosite.DefaultOpenIDConnectClient{
		DefaultClient: base, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlgorithm: string(jose.RS256),
		JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: "rsa-client", Algorithm: string(jose.RS256), Use: "sig"}}},
	}
	server.provider.(*fosite.Fosite).Store = &clientAssertionReplayStore{Storage: server.store, seen: make(map[string]time.Time)}
	server.provider.(*fosite.Fosite).Config.(*fosite.Config).TokenURL = oidcTestIssuer + "/oidc/token"
	validAssertion := signedClientAssertion(t, privateKey, "valid-control")
	decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {controlCode}, "redirect_uri": {testRedirectURI}, "code_verifier": {controlVerifier},
		"client_id": {testClientID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {validAssertion},
	}))
	for _, field := range []string{"n", "p", "q", "d"} {
		for _, format := range []string{"compact", "json"} {
			t.Run(field+"/"+format, func(t *testing.T) {
				key := map[string]string{"kty": "RSA", "n": "AQAB", "e": "AQAB"}
				key[field] = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 2049)))
				header, err := json.Marshal(map[string]any{"alg": "RS256", "jwk": key})
				if err != nil {
					t.Fatal(err)
				}
				protected := base64.RawURLEncoding.EncodeToString(header)
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"test-client","sub":"test-client"}`))
				assertion := protected + "." + payload + ".AA"
				if format == "json" {
					raw, err := json.Marshal(map[string]string{"protected": protected, "payload": payload, "signature": "AA"})
					if err != nil {
						t.Fatal(err)
					}
					assertion = string(raw)
					expected := "JWK contains private parameters"
					if field == "n" {
						expected = "modulus too large"
					}
					_, parseErr := jose.ParseSignedJSON(assertion, []jose.SignatureAlgorithm{jose.RS256})
					if !hasErrorInChain(parseErr, expected) {
						t.Fatalf("go-jose JSON parser error=%v, want %q", parseErr, expected)
					}
					return
				}
				// Introspection is Basic-only and rejects before parsing an assertion.
				for _, endpoint := range []struct {
					name      string
					handler   http.Handler
					basicGate bool
				}{{"token", server.TokenHandler(), false}, {"revocation", server.RevocationHandler(), true}} {
					values := url.Values{"client_id": {testClientID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}, "token": {issued.AccessToken}}
					request := httptest.NewRequest(http.MethodPost, "/oidc/"+endpoint.name, strings.NewReader(values.Encode()))
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					if endpoint.basicGate {
						request.SetBasicAuth(testClientID, testClientSecret)
					}
					if err := request.ParseForm(); err != nil {
						t.Fatal(err)
					}
					_, parseErr := server.provider.(*fosite.Fosite).AuthenticateClient(request.Context(), request, request.PostForm)
					expected := "JWK contains private parameters"
					if field == "n" {
						expected = "modulus too large"
					}
					if !hasErrorInChain(parseErr, expected) {
						t.Fatalf("%s assertion parser error=%v, want %q", endpoint.name, parseErr, expected)
					}
					response := httptest.NewRecorder()
					endpoint.handler.ServeHTTP(response, request)
					if response.Code < 400 || response.Code >= 500 {
						t.Fatalf("%s status=%d body=%s", endpoint.name, response.Code, response.Body.String())
					}
					var body map[string]any
					if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					if body["access_token"] != nil || body["refresh_token"] != nil {
						t.Fatalf("%s issued credentials", endpoint.name)
					}
				}
			})
		}
	}
	server.provider.(*fosite.Fosite).Store = server.store
	server.store.client = originalClient
	// All failed assertions must leave both the authorization code and existing
	// access token usable through the normal confidential-client boundary.
	decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	active := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	var body map[string]any
	if err := json.Unmarshal(active.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if active.Code != http.StatusOK || body["active"] != true {
		t.Fatalf("failed assertion consumed/revoked state: status=%d body=%s", active.Code, active.Body.String())
	}
}

func hasErrorInChain(err error, fragment string) bool {
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if strings.Contains(cause.Error(), fragment) {
			return true
		}
	}
	return false
}

func signedClientAssertion(t *testing.T, key *rsa.PrivateKey, jti string) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{
		"iss": testClientID, "sub": testClientID, "aud": oidcTestIssuer + "/oidc/token",
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "jti": jti,
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "rsa-client"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

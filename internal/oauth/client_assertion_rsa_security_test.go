package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/ory/fosite"
)

// clientAssertionReplayStore supplies Fosite's replay contract for the test;
// the production Store deliberately disables client assertion JWTs.
type clientAssertionReplayStore struct {
	fosite.Storage
	inspectionClient fosite.Client
	mu               sync.Mutex
	seen             map[string]time.Time
}

func (s *clientAssertionReplayStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if s.inspectionClient != nil && id == s.inspectionClient.GetID() {
		return s.inspectionClient, nil
	}
	return s.Storage.GetClient(ctx, id)
}

func (s *clientAssertionReplayStore) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expiry, ok := s.seen[jti]; ok && expiry.After(time.Now()) {
		return errors.New("client assertion jti already used")
	}
	delete(s.seen, jti)
	return nil
}

func (s *clientAssertionReplayStore) SetClientAssertionJWT(_ context.Context, jti string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.seen[jti]; ok && old.After(time.Now()) {
		return errors.New("client assertion jti already used")
	}
	s.seen[jti] = expiry
	return nil
}

func TestRSAClientAssertionAuthentication(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []jose.SignatureAlgorithm{jose.RS256, jose.PS256} {
		t.Run(string(algorithm), func(t *testing.T) {
			server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
			// Exercise the real handlers with a registered private_key_jwt client.
			// Production bootstrap registration is Basic; this fixture supplies OIDC metadata.
			secretHash := append([]byte(nil), server.store.client.GetHashedSecret()...)
			inspectionClient := &fosite.DefaultClient{ID: "inspection-client", Secret: secretHash, GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"}}
			server.provider.(*fosite.Fosite).Store = &clientAssertionReplayStore{Storage: server.store, inspectionClient: inspectionClient, seen: make(map[string]time.Time)}
			base := &fosite.DefaultClient{ID: testClientID, Secret: secretHash, GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"}}
			server.store.client = &fosite.DefaultOpenIDConnectClient{DefaultClient: base, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlgorithm: string(algorithm), JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "rsa-client", Algorithm: string(algorithm), Use: "sig"}}}}
			server.provider.(*fosite.Fosite).Config.(*fosite.Config).TokenURL = oidcTestIssuer + "/oidc/token"
			assertion := func(signingKey *rsa.PrivateKey, alg jose.SignatureAlgorithm, id string) string {
				claims, _ := json.Marshal(map[string]any{"iss": testClientID, "sub": testClientID, "aud": oidcTestIssuer + "/oidc/token", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "jti": id})
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, (&jose.SignerOptions{}).WithHeader("kid", "rsa-client"))
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
			request := func(handler http.Handler, raw string, token string, basicGate bool) *httptest.ResponseRecorder {
				values := url.Values{"client_id": {testClientID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {raw}, "grant_type": {"client_credentials"}, "scope": {"goauthy.read"}, "token": {token}}
				r := httptest.NewRequest(http.MethodPost, oidcTestIssuer+"/oidc/token", strings.NewReader(values.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if basicGate {
					// The route checks that Authorization is present before Fosite
					// authenticates the private_key_jwt assertion from the form.
					r.SetBasicAuth(testClientID, "unused")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			validTokenAssertion := assertion(key, algorithm, "valid-token")
			issued := decodeToken(t, request(server.TokenHandler(), validTokenAssertion, "", false))
			replayed := request(server.TokenHandler(), validTokenAssertion, "", false)
			if replayed.Code < 400 || !strings.Contains(replayed.Body.String(), "jti_known") {
				t.Fatalf("replayed assertion status=%d body=%s", replayed.Code, replayed.Body.String())
			}
			for _, endpoint := range []struct {
				name      string
				handler   http.Handler
				basicGate bool
			}{{"token", server.TokenHandler(), false}, {"revocation", server.RevocationHandler(), true}} {
				for _, kind := range []string{"none", "wrong-algorithm", "wrong-signature"} {
					id := fmt.Sprintf("%s-%s", endpoint.name, kind)
					raw := assertion(wrong, algorithm, id)
					if kind == "wrong-algorithm" {
						raw = assertion(key, jose.RS512, id)
					}
					if kind == "none" {
						raw = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "."
					}
					result := request(endpoint.handler, raw, issued.AccessToken, endpoint.basicGate)
					if result.Code < 400 || result.Code >= 500 {
						t.Fatalf("%s/%s status=%d body=%s", endpoint.name, kind, result.Code, result.Body.String())
					}
				}
			}
			active := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, inspectionClient.GetID(), testClientSecret)
			var body map[string]any
			if err := json.Unmarshal(active.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if active.Code != http.StatusOK || body["active"] != true {
				t.Fatalf("valid introspection status=%d body=%s", active.Code, active.Body.String())
			}
			revoked := request(server.RevocationHandler(), assertion(key, algorithm, "valid-revoke"), issued.AccessToken, true)
			if revoked.Code != http.StatusOK {
				t.Fatalf("valid revocation status=%d body=%s", revoked.Code, revoked.Body.String())
			}
		})
	}
}

package upstreamprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// signedIDToken signs a compact JWT suitable for ValidateIDToken verification.
// Unlike signedToken in jwks_verifier_test, this includes nonce, exp, and iat.
func signedIDToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience, nonce string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss":   issuer,
		"aud":   audience,
		"sub":   "oidc-subject",
		"nonce": nonce,
		"exp":   fixedNow.Add(time.Hour).Unix(),
		"iat":   fixedNow.Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testOnlyClientTrustedCA returns an http.Client trusting the TLS test CA.
func testOnlyClientTrustedCA(server *httptest.Server) *http.Client {
	return server.Client()
}

// boundaryHooks tracks Resolve and Complete calls for assertion.
type boundaryHooks struct {
	resolveCalls  atomic.Int32
	completeCalls atomic.Int32
}

func (h *boundaryHooks) hooks() LocalLoginHooks {
	return LocalLoginHooks{
		Prepare: func(_ *http.Request, interaction string) (string, string, string, error) {
			return testCanonicalTestToken, testCanonicalTestDigest, DigestSHA256(interaction), nil
		},
		Current: func(_ *http.Request) (string, string, error) {
			return testCanonicalTestToken, testCanonicalTestDigest, nil
		},
		Resolve: func(_ context.Context, _ SubjectResult) (string, error) {
			h.resolveCalls.Add(1)
			return "local-user", nil
		},
		Complete: func(w http.ResponseWriter, _ *http.Request, _, _, _ string, _ *OIDCSession) {
			h.completeCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		},
	}
}

func TestOIDCUserInfoBoundary(t *testing.T) {
	t.Parallel()
	const (
		oidcIssuer = "https://issuer.example.test"
		clientID   = "test-client"
		kid        = "key-1"
	)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// JWKS server (TLS): serves the signing public key.
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}},
		})
	}))
	defer jwksServer.Close()

	// UserInfo server (TLS): counts calls and returns valid identity.
	// Proves the endpoint IS reachable and WOULD return identity.
	var userInfoCalls atomic.Int32
	userInfoServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		userInfoCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":  "oidc-subject",
			"name": "Test User",
		})
	}))
	defer userInfoServer.Close()

	// Sanity: prove userinfo is reachable.
	resp, err := userInfoServer.Client().Get(userInfoServer.URL)
	if err != nil {
		t.Fatalf("userinfo unreachable: %v", err)
	}
	resp.Body.Close()

	// Single client trusting all TLS test servers.
	client := testOnlyClientTrustedCA(jwksServer)

	tests := []struct {
		name       string
		providerID string
		version    string // empty = legacy
		wrongNonce bool
	}{
		{"legacy_nonce_mismatch", "google", "", true},
		{"legacy_good_nonce", "google", "", false},
		{"managed_nonce_mismatch", managedID, "v1.0", true},
		{"managed_good_nonce", managedID, "v1.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userInfoCalls.Store(0)
			hooks := &boundaryHooks{}
			store := newTestStore()

			// Token server (TLS): returns a signed ID token.
			// Mismatch path uses a wrong nonce; good path reads
			// the transaction nonce from the store (safe because
			// the handler runs after start writes it).
			tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				var nonce string
				if tt.wrongNonce {
					nonce = "wrong-nonce-value"
				} else {
					store.mu.Lock()
					for _, tx := range store.transactions {
						nonce = tx.Nonce
						break
					}
					store.mu.Unlock()
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"access_token": "valid-access-token",
					"id_token":     signedIDToken(t, key, kid, oidcIssuer, clientID, nonce),
				})
			}))
			defer tokenServer.Close()

			cfg := Config{
				Issuer:                oidcIssuer,
				AuthorizationEndpoint: oidcIssuer + "/auth",
				TokenEndpoint:         tokenServer.URL,
				UserInfoEndpoint:      userInfoServer.URL,
				JWKSURI:               jwksServer.URL,
				ClientID:              clientID,
				Scopes:                []string{"openid", "profile"},
			}
			if tt.version != "" {
				cfg.ProviderSource = "registry"
				cfg.RuntimeVersion = tt.version
			}

			exchanger, err := NewOAuth2TokenExchanger(
				map[string]Config{tt.providerID: cfg},
				map[string]string{tt.providerID: "secret"},
				client,
			)
			if err != nil {
				t.Fatal(err)
			}

			verifier, err := NewJWKSVerifier(
				map[string]Config{tt.providerID: cfg},
				client,
			)
			if err != nil {
				t.Fatal(err)
			}

			h, err := NewLocalLoginHandler(
				map[string]Config{tt.providerID: cfg},
				store, exchanger, verifier,
				newCryptoProvider(newFixedRandom(make([]byte, 256))),
				map[string]bool{"https://app.example.com/callback": true},
				hooks.hooks(),
			)
			if err != nil {
				t.Fatal(err)
			}
			h.now = func() time.Time { return fixedNow }

			// Start: creates transaction with nonce.
			startRec := httptest.NewRecorder()
			startReq := httptest.NewRequest(http.MethodGet,
				"/upstream/"+tt.providerID+"/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil)
			startReq.SetPathValue("providerID", tt.providerID)
			h.LocalStartHandler().ServeHTTP(startRec, startReq)
			if startRec.Code != http.StatusFound {
				t.Fatalf("start status=%d body=%q", startRec.Code, startRec.Body.String())
			}
			stateCookie, _ := getCookies(t, startRec)
			startURL, _ := url.Parse(startRec.Header().Get("Location"))
			state := startURL.Query().Get("state")

			// Callback: exchange -> verify -> nonce check.
			cbRec := httptest.NewRecorder()
			cbReq := httptest.NewRequest(http.MethodGet,
				"/upstream/"+tt.providerID+"/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
			cbReq.SetPathValue("providerID", tt.providerID)
			if stateCookie != nil {
				cbReq.AddCookie(stateCookie)
			}
			h.LocalCallbackHandler().ServeHTTP(cbRec, cbReq)

			if tt.wrongNonce {
				if cbRec.Code != http.StatusBadRequest {
					t.Fatalf("nonce mismatch status=%d, want %d", cbRec.Code, http.StatusBadRequest)
				}
				if got := userInfoCalls.Load(); got != 0 {
					t.Fatalf("userinfo calls=%d, want 0 (nonce mismatch must fail before userinfo HTTP)", got)
				}
				if got := hooks.resolveCalls.Load(); got != 0 {
					t.Fatalf("resolve calls=%d, want 0", got)
				}
				if got := hooks.completeCalls.Load(); got != 0 {
					t.Fatalf("complete calls=%d, want 0", got)
				}
			} else {
				if cbRec.Code != http.StatusNoContent {
					t.Fatalf("good nonce status=%d, want %d body=%q", cbRec.Code, http.StatusNoContent, cbRec.Body.String())
				}
				if got := hooks.completeCalls.Load(); got != 1 {
					t.Fatalf("complete calls=%d, want 1", got)
				}
			}
		})
	}
}


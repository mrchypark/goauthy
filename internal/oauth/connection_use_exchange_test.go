package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestConnectionUseExchangeGateAndDPoPResourceAuth(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	connResource := "https://connections.example.test/api"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master"), []byte(base64.RawURLEncoding.EncodeToString(randomSecret(t))), 0600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{connResource}, OIDCConfig{
		Issuer:                oidcTestIssuer,
		LoadSigningKey:        func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ConnectionUseResource: connResource,
		ManagedClients:        clients.NewStore(db, keyring),
	})
	if err != nil {
		t.Fatal(err)
	}
	guard := func() (string, []any) { return "1", nil }
	consumer, err := server.store.managedClients.CreateWithGuard(context.Background(), clients.NewRequest{
		ID:            "async-consumer",
		Confidential:  true,
		RedirectURIs:  []string{"https://consumer.example.test/callback"},
		Scopes:        []string{"goauthy.connections.use"},
		DefaultScopes: []string{"goauthy.connections.use"},
		GrantTypes:    []string{TokenExchangeGrantType, "authorization_code"},
		Audiences:     []string{connResource},
		ForceMFA:      true,
	}, guard)
	if err != nil {
		t.Fatal(err)
	}
	consumerSecret, err := server.store.managedClients.ReadSecretWithGuard(context.Background(), consumer.ID, guard)
	if err != nil {
		t.Fatal(err)
	}

	// Issue a human MFA bearer token with goauthy.connections.use + connResource.
	seedOAuthUser(t, db, "alice")
	sid := oidcTestSessionID(1)
	if _, err := db.Execute(context.Background(), rhiza.ExecuteRequest{
		RequestID: "conn-use-seed-session",
		SQL:       `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?, 'alice', 'mfa', ?, ?, ?)`,
		Args:      []any{sid, time.Now().UTC().UnixMilli(), time.Now().UTC().Add(time.Hour).UnixMilli(), time.Now().UTC().UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authReq := httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id="+consumer.ID+"&response_type=code&redirect_uri="+url.QueryEscape("https://consumer.example.test/callback")+"&scope="+url.QueryEscape("goauthy.connections.use")+"&resource="+url.QueryEscape(connResource)+"&state=state-12345678&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	issueCode := func(sessionID, method string) string {
		rec := httptest.NewRecorder()
		server.CompleteAuthorizationWithSession(rec, authReq, "alice", []string{"goauthy.connections.use"}, time.Now().UTC(), sessionID, method)
		loc, parseErr := url.Parse(rec.Header().Get("Location"))
		if parseErr != nil || loc.Query().Get("code") == "" {
			t.Fatalf("authorize redirect=%q status=%d err=%v", rec.Header().Get("Location"), rec.Code, parseErr)
		}
		return loc.Query().Get("code")
	}
	code := issueCode(sid, oidcAuthMethodMFA)
	// Use authorization_code directly via token endpoint with basic auth.
	postConsumer := func(form url.Values, dpopHeader string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(consumer.ID, consumerSecret)
		if dpopHeader != "" {
			r.Header.Set("DPoP", dpopHeader)
		}
		w := httptest.NewRecorder()
		server.TokenHandler().ServeHTTP(w, r)
		return w
	}

	// Mint MFA human token via authorization_code.
	mfaCodeResp := postConsumer(url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://consumer.example.test/callback"}, "code_verifier": {verifier},
	}, "")
	if mfaCodeResp.Code != http.StatusOK {
		t.Fatalf("mfa code token status=%d body=%s", mfaCodeResp.Code, mfaCodeResp.Body.String())
	}
	humanToken := decodeToken(t, mfaCodeResp)

	// 2. Reject audience alias.
	if resp := postConsumer(url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {humanToken.AccessToken},
		"subject_token_type": {accessTokenType}, "scope": {"goauthy.connections.use"}, "audience": {connResource},
	}, ""); resp.Code != http.StatusBadRequest || tokenError(t, resp) != "invalid_target" {
		t.Fatalf("audience alias status=%d err=%q", resp.Code, tokenError(t, resp))
	}

	// 3. Reject missing DPoP header.
	exchForm := url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {humanToken.AccessToken},
		"subject_token_type": {accessTokenType}, "scope": {"goauthy.connections.use"}, "resource": {connResource},
	}
	if resp := postConsumer(exchForm, ""); resp.Code != http.StatusBadRequest || tokenError(t, resp) != "invalid_request" {
		t.Fatalf("missing DPoP status=%d err=%q", resp.Code, tokenError(t, resp))
	}

	// 4. DPoP nonce challenge then successful exchange.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chal := postConsumer(exchForm, dpopTestProof(t, priv, http.MethodPost, "/oidc/token", "conn-use-challenge-1", "", ""))
	if chal.Code != http.StatusBadRequest || tokenError(t, chal) != "use_dpop_nonce" || chal.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("challenge status=%d err=%q", chal.Code, tokenError(t, chal))
	}
	exchResp := postConsumer(exchForm, dpopTestProof(t, priv, http.MethodPost, "/oidc/token", "conn-use-exchange-2", chal.Header().Get("DPoP-Nonce"), ""))
	if exchResp.Code != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", exchResp.Code, exchResp.Body.String())
	}
	delegated := decodeToken(t, exchResp)
	if !strings.EqualFold(delegated.TokenType, "DPoP") {
		t.Fatalf("delegated token_type=%q; want DPoP", delegated.TokenType)
	}

	// 5. Reject multi-hop exchange.
	if resp := postConsumer(url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {delegated.AccessToken},
		"subject_token_type": {accessTokenType}, "scope": {"goauthy.connections.use"}, "resource": {connResource},
	}, dpopTestProof(t, priv, http.MethodPost, "/oidc/token", "conn-use-hop2-00003", "", "")); resp.Code != http.StatusBadRequest || tokenError(t, resp) != "invalid_grant" {
		t.Fatalf("second hop status=%d err=%q", resp.Code, tokenError(t, resp))
	}

	// 6. Resource endpoint: Bearer rejected with WWW-Authenticate: DPoP algs="ES256" error="invalid_token".
	bearerReq := httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/g1/credential", nil)
	bearerReq.Header.Set("Authorization", "Bearer "+delegated.AccessToken)
	w := httptest.NewRecorder()
	if _, _, _, ok := server.AuthorizeConnectionUseHTTP(w, bearerReq, connResource); ok || w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("bearer on DPoP token ok=%v code=%d www=%q", ok, w.Code, w.Header().Get("WWW-Authenticate"))
	}

	// 7. Resource endpoint: DPoP without nonce succeeds via MarkReplay; replay of same jti returns 401 invalid_dpop_proof.
	resProof := dpopTestProof(t, priv, http.MethodPost, "/auth/v1/connection-grants/g1/credential", "res-jti-0000000001", "", delegated.AccessToken)
	dpopReq := httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/g1/credential", nil)
	dpopReq.Header.Set("Authorization", "DPoP "+delegated.AccessToken)
	dpopReq.Header.Set("DPoP", resProof)
	w = httptest.NewRecorder()
	owner, cid, auth, ok := server.AuthorizeConnectionUseHTTP(w, dpopReq, connResource)
	if !ok || owner != "alice" || cid != consumer.ID || auth == nil {
		t.Fatalf("AuthorizeConnectionUseHTTP failed ok=%v owner=%q cid=%q code=%d", ok, owner, cid, w.Code)
	}

	// Replay same jti.
	w = httptest.NewRecorder()
	if _, _, _, ok := server.AuthorizeConnectionUseHTTP(w, dpopReq, connResource); ok || w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`) {
		t.Fatalf("replay ok=%v code=%d www=%q", ok, w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

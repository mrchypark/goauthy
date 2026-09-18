package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/rhiza"
)

// TestAuthorizationCodeClientBinding proves that an authorization code issued to
// client A cannot be redeemed by client B even when both share the same
// registered redirect URI. Cross-client redemption attempts must not consume
// the code. After a successful first redemption by A exactly one durable
// access-token row exists. A replay by A fails and Fosite v0.49 revokes the
// associated access and refresh tokens.
func TestAuthorizationCodeClientBinding(t *testing.T) {
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	server := oauthTestServer(t, db, randomSecret(t))
	ctx := t.Context()

	const sharedRedirectURI = "https://rp.example.test/callback"

	clientA, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID:                "client-a",
		RedirectURIs:            []string{sharedRedirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"goauthy.read", "offline_access"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic,
		Name:                    "Client A",
	})
	if err != nil {
		t.Fatal(err)
	}

	clientB, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID:                "client-b",
		RedirectURIs:            []string{sharedRedirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"goauthy.read", "offline_access"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic,
		Name:                    "Client B",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Issue an S256-PKCE authorization code for client A.
	verifier := strings.Repeat("x", 43)
	digest := sha256.Sum256([]byte(verifier))
	authorizeValues := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientA.ClientID},
		"redirect_uri":          {sharedRedirectURI},
		"scope":                 {"goauthy.read offline_access"},
		"state":                 {strings.Repeat("s", 32)},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	response := httptest.NewRecorder()
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+authorizeValues.Encode(), nil), "user-1", []string{"goauthy.read", "offline_access"})
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code issued")
	}

	// --- Attempt 1: client B authenticates with its own client_secret_basic ---
	respB1 := postTokenWithCredentials(server, clientB.ClientID, clientB.ClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {sharedRedirectURI},
		"code_verifier": {verifier},
	})
	if respB1.Code == http.StatusOK {
		t.Fatalf("client B with own credentials unexpectedly succeeded: %s", respB1.Body.String())
	}
	assertTokenCount(t, db, 0)

	// --- Attempt 2: client B substitutes client_id in the body only (no auth) ---
	respB2 := postTokenWithoutAuth(server, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {sharedRedirectURI},
		"client_id":     {clientB.ClientID},
		"code_verifier": {verifier},
	})
	if respB2.Code == http.StatusOK {
		t.Fatalf("client_id body substitution without auth unexpectedly succeeded: %s", respB2.Body.String())
	}
	assertTokenCount(t, db, 0)

	// --- Client A redeems the code (must succeed exactly once) ---
	respA := postTokenWithCredentials(server, clientA.ClientID, clientA.ClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {sharedRedirectURI},
		"code_verifier": {verifier},
	})
	if respA.Code != http.StatusOK {
		t.Fatalf("client A redemption failed: status=%d body=%s", respA.Code, respA.Body.String())
	}
	var tokenA tokenResponse
	if err := json.Unmarshal(respA.Body.Bytes(), &tokenA); err != nil || tokenA.AccessToken == "" {
		t.Fatalf("client A token response invalid: %#v err=%v", tokenA, err)
	}

	// Exactly one access token row exists and the token is retrievable via
	// introspection (the canonical store-path check for HMAC-signed tokens).
	assertTokenCount(t, db, 1)
	assertTokenActive(t, server, tokenA.AccessToken)

	// --- Replay: client A tries to redeem the same code again ---
	respReplay := postTokenWithCredentials(server, clientA.ClientID, clientA.ClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {sharedRedirectURI},
		"code_verifier": {verifier},
	})
	if respReplay.Code == http.StatusOK {
		t.Fatalf("replay of consumed code unexpectedly succeeded: %s", respReplay.Body.String())
	}

	// Fosite v0.49 revokes the associated access and refresh tokens when an
	// already-invalidated code is replayed. Both tables must be empty.
	assertAccessRowsZero(t, db)
	assertRefreshRowsZero(t, db)
}

func postTokenWithCredentials(server *Server, clientID, clientSecret string, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}

func postTokenWithoutAuth(server *Server, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}

func assertTokenCount(t *testing.T, db *rhiza.DB, want int64) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatalf("token count query failed: %v", err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("unexpected token count result: %#v", result.Rows)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("invalid token count type: %T", result.Rows[0][0])
	}
	if count != want {
		t.Fatalf("access token row count = %d, want %d", count, want)
	}
}

func assertTokenActive(t *testing.T, server *Server, tokenValue string) {
	t.Helper()
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {tokenValue}}, testClientID, testClientSecret)
	if response.Code != http.StatusOK {
		t.Fatalf("introspection status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("introspection decode failed: %v", err)
	}
	if !body.Active {
		t.Fatalf("token is not active after successful redemption: %s", response.Body.String())
	}
}

func assertAccessRowsZero(t *testing.T, db *rhiza.DB) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatalf("access token count query failed: %v", err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("unexpected result: %#v", result.Rows)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("invalid count type: %T", result.Rows[0][0])
	}
	if count != 0 {
		t.Fatalf("access token rows = %d after replay, want 0", count)
	}
}

func assertRefreshRowsZero(t *testing.T, db *rhiza.DB) {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM oauth_refresh_tokens`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatalf("refresh token count query failed: %v", err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("unexpected result: %#v", result.Rows)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("invalid count type: %T", result.Rows[0][0])
	}
	if count != 0 {
		t.Fatalf("refresh token rows = %d after replay, want 0", count)
	}
}

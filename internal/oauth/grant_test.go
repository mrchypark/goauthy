package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	testClientID     = "browser-client"
	testClientSecret = "correct-horse-battery-staple"
	testRedirectURI  = "http://localhost/callback"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
}

func TestAuthorizationCodePKCEAndRefreshRotation(t *testing.T) {
	db := oauthTestDB(t)
	hmacSecret := randomSecret(t)
	server := oauthTestServer(t, db, hmacSecret)
	verifier := strings.Repeat("a", 43)

	code := issueCode(t, server, verifier)
	wrong := postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("b", 43)},
	})
	if wrong.Code == http.StatusOK {
		t.Fatal("wrong PKCE verifier accepted")
	}

	// A failed verifier must not consume the code or its PKCE challenge.
	restarted := oauthTestServer(t, db, hmacSecret)
	issued := decodeToken(t, postToken(restarted, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	if issued.AccessToken == "" || issued.RefreshToken == "" || issued.TokenType != "bearer" || issued.Scope != "goauthy.read offline_access" {
		t.Fatalf("unexpected code exchange: %#v", issued)
	}
	rotated := decodeToken(t, postToken(restarted, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken},
	}))
	if rotated.AccessToken == "" || rotated.RefreshToken == "" || rotated.RefreshToken == issued.RefreshToken {
		t.Fatalf("refresh token did not rotate: %#v", rotated)
	}

	reuse := postToken(restarted, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken},
	})
	if reuse.Code == http.StatusOK {
		t.Fatal("rotated refresh token was reused")
	}
	assertTokenGrantRevoked(t, db)
}

func TestAuthorizationCodeIsSingleUseUnderConcurrency(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	verifier := strings.Repeat("c", 43)
	code := issueCode(t, server, verifier)

	start := make(chan struct{})
	results := make(chan int, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			response := postToken(server, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
			})
			results <- response.Code
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for status := range results {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent code exchanges succeeded %d times", successes)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("access token rows=%#v err=%v", rows.Rows, err)
	}
	count, ok := rows.Rows[0][0].(int64)
	if !ok || count > 1 {
		t.Fatalf("access token rows=%#v", rows.Rows)
	}
}

func TestAuthorizationRequiresS256PKCE(t *testing.T) {
	db := oauthTestDB(t)
	seedAccountExpiry(t, db, nil)
	server := oauthTestServer(t, db, randomSecret(t))
	for _, values := range []url.Values{
		{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)}},
		{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)}, "code_challenge": {strings.Repeat("x", 43)}, "code_challenge_method": {"plain"}},
	} {
		response := httptest.NewRecorder()
		server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read"})
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil || location.Query().Get("error") != "invalid_request" || location.Query().Get("code") != "" {
			t.Fatalf("PKCE request location=%q err=%v", response.Header().Get("Location"), err)
		}
	}
}

func TestAuthorizationRejectsMissingLoginAndRedirectMismatch(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	verifier := strings.Repeat("d", 43)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI},
		"scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	response := httptest.NewRecorder()
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "", []string{"goauthy.read"})
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "access_denied" || location.Query().Get("code") != "" {
		t.Fatalf("missing-login location=%q err=%v", response.Header().Get("Location"), err)
	}

	code := issueCode(t, server, verifier)
	mismatch := postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost/wrong"}, "code_verifier": {verifier},
	})
	if mismatch.Code == http.StatusOK {
		t.Fatal("redirect URI mismatch accepted")
	}
}

func TestAuthorizationIssueRemovesExpiredState(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	issueCode(t, server, strings.Repeat("e", 43))
	issueCode(t, server, strings.Repeat("g", 43))
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "expire-oauth-test-state",
		Statements: []rhiza.SQLStatement{
			{SQL: `UPDATE oauth_authorize_codes SET expires_at_unix_ms = 0 WHERE signature = (SELECT signature FROM oauth_authorize_codes ORDER BY signature LIMIT 1)`},
			{SQL: `UPDATE oauth_pkce_requests SET expires_at_unix_ms = 0 WHERE signature = (SELECT signature FROM oauth_pkce_requests ORDER BY signature LIMIT 1)`},
		},
	}); err != nil {
		t.Fatal(err)
	}
	issueCode(t, server, strings.Repeat("f", 43))
	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT (SELECT COUNT(*) FROM oauth_authorize_codes),
			(SELECT COUNT(*) FROM oauth_pkce_requests)`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(2) || result.Rows[0][1] != int64(2) {
		t.Fatalf("expired authorization state retained: rows=%#v err=%v", result.Rows, err)
	}
}

func TestTokenIssueRemovesExpiredState(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	for index, verifier := range []string{strings.Repeat("h", 43), strings.Repeat("i", 43)} {
		if index == 1 {
			if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
				RequestID: "expire-token-test-state",
				Statements: []rhiza.SQLStatement{
					{SQL: `UPDATE oauth_access_tokens SET expires_at_unix_ms = 0`},
					{SQL: `UPDATE oauth_refresh_tokens SET expires_at_unix_ms = 0`},
				},
			}); err != nil {
				t.Fatal(err)
			}
		}
		code := issueCode(t, server, verifier)
		decodeToken(t, postToken(server, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
		}))
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens),
			(SELECT COUNT(*) FROM oauth_refresh_tokens)`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) || result.Rows[0][1] != int64(1) {
		t.Fatalf("expired token state retained: rows=%#v err=%v", result.Rows, err)
	}
}

func oauthTestDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func oauthTestServer(t *testing.T, db *rhiza.DB, hmacSecret []byte) *Server {
	t.Helper()
	server, err := NewServer(context.Background(), db, hmacSecret, testClientID, testClientSecret, testRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func issueCode(t *testing.T, server *Server, verifier string) string {
	t.Helper()
	seedOAuthUser(t, server.store.db, "user-1")
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI},
		"scope": {"goauthy.read offline_access"}, "state": {strings.Repeat("s", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	response := httptest.NewRecorder()
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read", "offline_access"})
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return location.Query().Get("code")
}

func seedOAuthUser(t *testing.T, db *rhiza.DB, subject string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "seed-oauth-user-" + subject,
		SQL:       `INSERT OR IGNORE INTO identity_users (subject,username,password_phc) VALUES (?, ?, ?)`,
		Args:      []any{subject, subject, "phc"},
	}); err != nil {
		t.Fatal(err)
	}
}

func postToken(server *Server, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}

func decodeToken(t *testing.T, response *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	var token tokenResponse
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("token status=%d response=%#v body=%s", response.Code, token, response.Body.String())
	}
	return token
}

func assertTokenGrantRevoked(t *testing.T, db *rhiza.DB) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens),
			(SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active = 1)`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) || result.Rows[0][1] != int64(0) {
		t.Fatalf("token grant not revoked: rows=%#v err=%v", result.Rows, err)
	}
}

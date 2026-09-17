package oauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

const oidcTestIssuer = "https://issuer.example.test"

var oidcTestAuthTime = time.Unix(1_700_000_000, 0).UTC()

func TestOIDCNonceBoundaryAndOAuthOnlyRejection(t *testing.T) {
	db := oauthTestDB(t)
	oauthOnly := oauthTestServer(t, db, randomSecret(t))
	values := oidcAuthorizationValues(strings.Repeat("a", 43), "nonce")
	if _, err := oauthOnly.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)); err != ErrInvalidAuthorizationRequest {
		t.Fatalf("OAuth-only server accepted openid: %v", err)
	}
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	for _, test := range []struct {
		name  string
		nonce []string
	}{
		{name: "duplicate", nonce: []string{"one", "two"}},
		{name: "empty", nonce: []string{""}},
		{name: "oversized", nonce: []string{strings.Repeat("n", maxNonceLength+1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := cloneValues(values)
			request["nonce"] = test.nonce
			if _, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+request.Encode(), nil)); err != ErrInvalidAuthorizationRequest {
				t.Fatalf("invalid nonce accepted: %v", err)
			}
		})
	}
}

func TestOIDCAuthorizationCodeAndRefreshIDTokens(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	authTime := oidcTestAuthTime
	sid := oidcTestSessionID(0)
	for _, test := range []struct{ method, wantAMR string }{{oidcAuthMethodPwd, "pwd"}, {oidcAuthMethodWebAuthn, "mfa"}, {oidcAuthMethodMFA, "mfa"}, {oidcAuthMethodExternal, "external"}} {
		t.Run(test.method, func(t *testing.T) {
			verifier := strings.Repeat(test.method[:1], 43)
			code := issueOIDCCodeWithMethod(t, server, verifier, "nonce-value", authTime, sid, test.method)
			issued := decodeOIDCToken(t, postToken(server, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
			}))
			claims := verifyOIDCTestToken(t, issued.IDToken, key, time.Now().UTC())
			if claims.Nonce != "nonce-value" || claims.SessionID != sid || !claims.AuthTime.Equal(authTime) || claims.AuthorizedParty != testClientID || strings.Join(claims.AuthenticationMethods, ",") != test.wantAMR || claims.AccessTokenHash != oidc.AccessTokenHash(issued.AccessToken) {
				t.Fatalf("unexpected ID-token claims: %#v", claims)
			}
			refreshed := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
			claims = verifyOIDCTestToken(t, refreshed.IDToken, key, time.Now().UTC())
			if claims.Nonce != "" || claims.SessionID != sid || !claims.AuthTime.Equal(authTime) || strings.Join(claims.AuthenticationMethods, ",") != test.wantAMR || claims.AccessTokenHash != oidc.AccessTokenHash(refreshed.AccessToken) {
				t.Fatalf("unexpected refreshed ID-token claims: %#v", claims)
			}
		})
	}
}

func TestOIDCSigningKeyLoadsOncePerIDTokenResponse(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	loads := 0
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) {
		loads++
		return key, nil
	})

	verifier := strings.Repeat("k", 43)
	issued := decodeOIDCToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime, oidcTestSessionID(0))}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	if loads != 2 {
		t.Fatalf("authorization-code signing-key loads=%d, want 2", loads)
	}
	decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
	if loads != 4 {
		t.Fatalf("refresh signing-key loads=%d, want 4", loads)
	}

	nonOIDCVerifier := strings.Repeat("l", 43)
	decodeOIDCToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueNonOIDCCode(t, server, nonOIDCVerifier)}, "redirect_uri": {testRedirectURI}, "code_verifier": {nonOIDCVerifier},
	}))
	if loads != 5 {
		t.Fatalf("non-OIDC authorization-code loaded signing key: %d", loads)
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || loads != 6 {
		t.Fatalf("non-OIDC client credentials status=%d signing-key loads=%d", response.Code, loads)
	}
}

func TestOIDCDoesNotIssueWithoutOpenIDOrForClientCredentials(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	code := issueNonOIDCCode(t, server, strings.Repeat("c", 43))
	if got := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("c", 43)}})); got.IDToken != "" {
		t.Fatalf("non-openid grant returned ID token")
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"openid"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_scope"`) {
		t.Fatalf("client credentials openid status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRevokeOIDCSessionInvalidatesTokensAndPendingCode(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	sidOne := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	sidTwoBytes := make([]byte, 32)
	sidTwoBytes[0] = 1
	sidTwo := base64.RawURLEncoding.EncodeToString(sidTwoBytes)
	verifierOne, verifierTwo, pendingVerifier := strings.Repeat("f", 43), strings.Repeat("g", 43), strings.Repeat("h", 43)

	issuedOne := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueOIDCCode(t, server, verifierOne, "one", oidcTestAuthTime, sidOne)}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifierOne}}))
	rotatedOne := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issuedOne.RefreshToken}}))
	issuedTwo := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueOIDCCode(t, server, verifierTwo, "two", oidcTestAuthTime, sidTwo)}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifierTwo}}))
	pendingCode := issueOIDCCode(t, server, pendingVerifier, "pending", oidcTestAuthTime, sidOne)

	if err := server.RevokeOIDCSession(context.Background(), sidOne); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT revoked_at_unix_ms FROM browser_sessions WHERE token_digest = ?`, Args: []any{sidOne}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] == nil {
		t.Fatalf("logout did not atomically revoke browser session: rows=%#v err=%v", result.Rows, err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), rotatedOne.AccessToken), &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("revoked access token err=%v", err)
	}
	if response := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rotatedOne.RefreshToken}}); response.Code == http.StatusOK {
		t.Fatal("revoked refresh token issued tokens")
	}
	if response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {pendingCode}, "redirect_uri": {testRedirectURI}, "code_verifier": {pendingVerifier}}); response.Code == http.StatusOK {
		t.Fatal("logout-invalidated authorization code issued tokens")
	}
	postLogoutVerifier := strings.Repeat("i", 43)
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+oidcAuthorizationValues(postLogoutVerifier, "post-logout").Encode(), nil), "user-1", []string{"openid", "goauthy.read", "offline_access"}, oidcTestAuthTime, sidOne, oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") != "" {
		t.Fatalf("revoked browser session issued code: status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	if err := server.RevokeOIDCSession(context.Background(), sidOne); err != nil {
		t.Fatal(err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), issuedTwo.AccessToken), &fosite.DefaultSession{}); err != nil {
		t.Fatalf("other session access token err=%v", err)
	}
	if response := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issuedTwo.RefreshToken}}); response.Code != http.StatusOK {
		t.Fatalf("other session refresh status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRevokeOIDCSessionRejectsInvalidID(t *testing.T) {
	db := oauthTestDB(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	if err := server.RevokeOIDCSession(context.Background(), "not-a-session-id"); err == nil {
		t.Fatal("invalid OIDC session ID accepted")
	}
	if err := oauthTestServer(t, db, randomSecret(t)).RevokeOIDCSession(context.Background(), base64.RawURLEncoding.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("OAuth-only server accepted OIDC session revocation")
	}
}

func TestOIDCBackchannelNetworkExceptionsRequireEndpoint(t *testing.T) {
	_, err := NewServerWithOIDC(context.Background(), oauthTestDB(t), randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		BackChannelLogoutAllowHTTP: true,
	})
	if err == nil {
		t.Fatal("back-channel HTTP exception was accepted without an endpoint")
	}
}

func TestOIDCBackchannelAssociationIsCreatedOnlyAfterExchangeAndFanoutIsOnce(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil },
		BackChannelLogoutURI: "https://rp.example.test/backchannel",
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := oidcTestSessionID(9)
	verifier := strings.Repeat("u", 43)
	code := issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime, sid)
	assertBackchannelRows(t, db, sid, 0, 0)
	assertUserClientRows(t, db, 0)
	if response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("v", 43)}}); response.Code == http.StatusOK {
		t.Fatal("invalid code verifier issued tokens")
	}
	assertBackchannelRows(t, db, sid, 0, 0)
	assertUserClientRows(t, db, 0)
	decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	assertBackchannelRows(t, db, sid, 1, 0)
	assertUserClientRows(t, db, 1)

	if err := server.RevokeOIDCSession(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	assertBackchannelRows(t, db, sid, 0, 1)
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT logout_uri, allow_private, allow_http, attempts FROM oidc_backchannel_deliveries WHERE sid = ?`, Args: []any{sid}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 4 || result.Rows[0][0] != "https://rp.example.test/backchannel" || result.Rows[0][1] != int64(0) || result.Rows[0][2] != int64(0) || result.Rows[0][3] != int64(0) {
		t.Fatalf("delivery=%#v err=%v", result.Rows, err)
	}
	if err := server.RevokeOIDCSession(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	assertBackchannelRows(t, db, sid, 0, 1)
	assertUserClientRows(t, db, 1)
}

func assertUserClientRows(t *testing.T, db *rhiza.DB, want int64) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oidc_user_clients WHERE subject='user-1' AND client_id=? AND logout_uri='https://rp.example.test/backchannel' AND allow_private=0 AND allow_http=0`, Args: []any{testClientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != want {
		t.Fatalf("user/client mapping count=%v err=%v", result.Rows, err)
	}
}

func TestOIDCUserClientInsertFailureRollsBackIssuance(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil },
		BackChannelLogoutURI: "https://rp.example.test/backchannel",
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := oidcTestSessionID(35)
	verifier := strings.Repeat("q", 43)
	code := issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime, sid)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "user-client-sink-failure", SQL: `CREATE TRIGGER reject_user_client BEFORE INSERT ON oidc_user_clients BEGIN SELECT RAISE(ABORT,'user client unavailable'); END`}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}
	if response := postToken(server, form); response.Code == http.StatusOK {
		t.Fatal("token issuance succeeded without recording logged-in RP")
	}
	assertBackchannelRows(t, db, sid, 0, 0)
	assertUserClientRows(t, db, 0)
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens),(SELECT COUNT(*) FROM oauth_refresh_tokens),(SELECT COUNT(*) FROM oauth_authorize_codes WHERE used_attempt IS NOT NULL)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) || result.Rows[0][1] != int64(0) || result.Rows[0][2] != int64(0) {
		t.Fatalf("issuance leaked state: %v err=%v", result.Rows, err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "user-client-sink-restored", SQL: `DROP TRIGGER reject_user_client`}); err != nil {
		t.Fatal(err)
	}
	decodeOIDCToken(t, postToken(server, form))
	assertUserClientRows(t, db, 1)
}

func TestOIDCBackchannelExchangeVsLogoutLeavesNoAssociation(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil },
		BackChannelLogoutURI: "https://rp.example.test/backchannel",
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := oidcTestSessionID(10)
	verifier := strings.Repeat("w", 43)
	code := issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime, sid)
	start := make(chan struct{})
	done := make(chan error, 2)
	go func() {
		<-start
		_ = postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})
		done <- nil
	}()
	go func() {
		<-start
		done <- server.RevokeOIDCSession(context.Background(), sid)
	}()
	close(start)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	assertBackchannelRows(t, db, sid, 0, -1)
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT
		(SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid = ?),
		(SELECT revoked_at_unix_ms IS NOT NULL FROM browser_sessions WHERE token_digest = ?),
		(SELECT COUNT(*) FROM oauth_access_tokens)`, Args: []any{sid, sid}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 3 || result.Rows[0][0].(int64) > 1 || result.Rows[0][1] != int64(1) || result.Rows[0][2] != int64(0) {
		t.Fatalf("exchange/logout state=%#v err=%v", result.Rows, err)
	}
}

func assertBackchannelRows(t *testing.T, db *rhiza.DB, sid string, mappings, deliveries int64) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT
		(SELECT COUNT(*) FROM oidc_session_clients WHERE sid = ?),
		(SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid = ?)`, Args: []any{sid, sid}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 || result.Rows[0][0] != mappings || (deliveries >= 0 && result.Rows[0][1] != deliveries) {
		t.Fatalf("backchannel sid=%q rows=%#v want mappings=%d deliveries=%d err=%v", sid, result.Rows, mappings, deliveries, err)
	}
}

func TestOIDCKeyLoadFailureDoesNotConsumeAuthorizationCode(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	mode := 0
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) {
		if mode == 0 {
			return oidc.SigningKey{}, errors.New("unavailable")
		}
		if mode == 1 {
			return oidc.SigningKey{}, nil
		}
		return key, nil
	})
	verifier := strings.Repeat("d", 43)
	code := issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime.Add(-time.Minute), oidcTestSessionID(0))
	if response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}); response.Code == http.StatusOK {
		t.Fatal("key-loader failure issued tokens")
	}
	mode = 1
	if response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}); response.Code == http.StatusOK {
		t.Fatal("invalid signing key issued tokens")
	}
	mode = 2
	if got := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})); got.IDToken == "" {
		t.Fatal("authorization code was consumed before signing key loaded")
	}
}

func TestOIDCMalformedStoredAuthMethodDoesNotConsumeAuthorizationCode(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	verifier := strings.Repeat("e", 43)
	code := issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime.Add(-time.Minute), oidcTestSessionID(0))
	originalCode, originalPKCE := storedOIDCRequests(t, db)
	malformedCode := removeOIDCAuthMethod(t, originalCode)
	malformedPKCE := removeOIDCAuthMethod(t, originalPKCE)
	setStoredOIDCRequests(t, db, malformedCode, malformedPKCE, "malformed")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}
	if response := postToken(server, form); response.Code == http.StatusOK {
		t.Fatal("malformed OIDC claims issued tokens")
	}
	setStoredOIDCRequests(t, db, originalCode, originalPKCE, "restore")
	if got := decodeOIDCToken(t, postToken(server, form)); got.IDToken == "" {
		t.Fatal("malformed OIDC claims consumed authorization code")
	}
}

func TestOIDCSessionClaimsRejectMissingAndMalformedAuthMethod(t *testing.T) {
	valid := map[string]interface{}{
		oidcAuthTimeExtra: "1", oidcSessionIDExtra: oidcTestSessionID(0), oidcNonceExtra: "nonce", oidcAuthMethodExtra: oidcAuthMethodPwd,
	}
	for name, extra := range map[string]map[string]interface{}{
		"missing":   {oidcAuthTimeExtra: "1", oidcSessionIDExtra: oidcTestSessionID(0), oidcNonceExtra: "nonce"},
		"malformed": {oidcAuthTimeExtra: "1", oidcSessionIDExtra: oidcTestSessionID(0), oidcNonceExtra: "nonce", oidcAuthMethodExtra: "password"},
		"valid":     valid,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, err := oidcSessionClaims(extra)
			if (name == "valid") != (err == nil) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func removeOIDCAuthMethod(t *testing.T, encoded string) string {
	t.Helper()
	var record requestRecord
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		t.Fatal(err)
	}
	delete(record.Extra, oidcAuthMethodExtra)
	malformed, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(malformed)
}

func storedOIDCRequests(t *testing.T, db *rhiza.DB) (string, string) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT request_json FROM oauth_authorize_codes LIMIT 1), (SELECT request_json FROM oauth_pkce_requests LIMIT 1)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("stored OIDC request rows=%#v err=%v", result.Rows, err)
	}
	code, codeOK := result.Rows[0][0].(string)
	pkce, pkceOK := result.Rows[0][1].(string)
	if !codeOK || !pkceOK {
		t.Fatalf("stored OIDC request types=%T,%T", result.Rows[0][0], result.Rows[0][1])
	}
	return code, pkce
}

func setStoredOIDCRequests(t *testing.T, db *rhiza.DB, code, pkce, suffix string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "oidc-test-claims-" + suffix, Statements: []rhiza.SQLStatement{
		{SQL: `UPDATE oauth_authorize_codes SET request_json = ?`, Args: []any{code}},
		{SQL: `UPDATE oauth_pkce_requests SET request_json = ?`, Args: []any{pkce}},
	}}); err != nil {
		t.Fatal(err)
	}
}

type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func oidcTestServer(t *testing.T, db *rhiza.DB, secret []byte, loader func(context.Context) (oidc.SigningKey, error)) *Server {
	t.Helper()
	server, err := NewServerWithOIDC(context.Background(), db, secret, testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: loader})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func oidcAuthorizationValues(verifier, nonce string) url.Values {
	digest := sha256.Sum256([]byte(verifier))
	return url.Values{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "scope": {"openid goauthy.read offline_access"}, "state": {strings.Repeat("s", 32)}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
}

func issueOIDCCode(t *testing.T, server *Server, verifier, nonce string, authTime time.Time, sessionID string) string {
	return issueOIDCCodeWithMethod(t, server, verifier, nonce, authTime, sessionID, oidcAuthMethodPwd)
}

func issueOIDCCodeWithMethod(t *testing.T, server *Server, verifier, nonce string, authTime time.Time, sessionID, authMethod string) string {
	t.Helper()
	seedOAuthUser(t, server.store.db, "user-1")
	ensureOIDCTestBrowserSession(t, server, sessionID)
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+oidcAuthorizationValues(verifier, nonce).Encode(), nil), "user-1", []string{"openid", "goauthy.read", "offline_access"}, authTime, sessionID, authMethod)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("OIDC authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return location.Query().Get("code")
}

func oidcTestSessionID(first byte) string {
	sid := make([]byte, 32)
	sid[0] = first
	return base64.RawURLEncoding.EncodeToString(sid)
}

func ensureOIDCTestBrowserSession(t *testing.T, server *Server, sessionID string) {
	t.Helper()
	if !validOIDCSessionID(sessionID) {
		t.Fatalf("invalid OIDC test session ID %q", sessionID)
	}
	result, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT 1 FROM browser_sessions WHERE token_digest = ?`, Args: []any{sessionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 0 {
		return
	}
	now := time.Now().UTC().UnixMilli()
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "oidc-test-session-" + sessionID, SQL: `INSERT INTO browser_sessions (token_digest, subject, created_at_unix_ms, expires_at_unix_ms, last_seen_at_unix_ms) VALUES (?, ?, ?, ?, ?)`, Args: []any{sessionID, "user-1", now, now + int64(time.Hour/time.Millisecond), now}}); err != nil {
		t.Fatal(err)
	}
}

func issueNonOIDCCode(t *testing.T, server *Server, verifier string) string {
	t.Helper()
	seedOAuthUser(t, server.store.db, "user-1")
	sessionID := oidcTestSessionID(11)
	ensureOIDCTestBrowserSession(t, server, sessionID)
	values := oidcAuthorizationValues(verifier, "")
	values.Set("scope", "goauthy.read offline_access")
	values.Del("nonce")
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read", "offline_access"}, oidcTestAuthTime, sessionID, oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return location.Query().Get("code")
}

func decodeOIDCToken(t *testing.T, response *httptest.ResponseRecorder) oidcTokenResponse {
	t.Helper()
	var token oidcTokenResponse
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || response.Code != http.StatusOK {
		t.Fatalf("token status=%d token=%#v body=%s err=%v", response.Code, token, response.Body.String(), err)
	}
	return token
}

func oidcTestKey(t *testing.T) oidc.SigningKey {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	return oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "test-key", Algorithm: "EdDSA", Use: "sig"}}
}

func verifyOIDCTestToken(t *testing.T, token string, key oidc.SigningKey, now time.Time) oidc.IDTokenClaims {
	t.Helper()
	claims, err := oidc.VerifyIDToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, oidcTestIssuer, testClientID, now)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestOIDCCodeRecordsLoginWithoutBackchannelURI(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }})
	if err != nil {
		t.Fatal(err)
	}
	sid := oidcTestSessionID(19)
	verifier := strings.Repeat("u", 43)
	code := issueOIDCCode(t, server, verifier, "nonce", oidcTestAuthTime, sid)
	decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT client_id,logout_uri FROM oidc_user_clients WHERE subject='user-1'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != testClientID || rows.Rows[0][1] != "" {
		t.Fatalf("URI-less code login: %+v %v", rows, err)
	}
	assertBackchannelRows(t, db, sid, 1, 0)
	if err := server.RevokeOIDCSession(t.Context(), sid); err != nil {
		t.Fatal(err)
	}
	assertBackchannelRows(t, db, sid, 0, 0)

}

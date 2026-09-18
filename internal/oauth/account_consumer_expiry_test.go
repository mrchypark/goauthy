package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestAlreadyIssuedUserTokenIntrospectionBecomesInactiveAfterAccountShortening(t *testing.T) {
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	token := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(t, server, strings.Repeat("e", 43))},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("e", 43)},
	}))
	setConsumerExpiryClock(server)
	shortenAccountExpiryAt(t, server.store.db, "user-1", consumerExpiryNow)
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token.AccessToken}}, testClientID, testClientSecret))
}

func TestShortenedAccountRefreshIsInactiveAndRevocationRemainsFinal(t *testing.T) {
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	token := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(t, server, strings.Repeat("r", 43))},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("r", 43)},
	}))
	setConsumerExpiryClock(server)
	shortenAccountExpiryAt(t, server.store.db, "user-1", consumerExpiryNow)
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token.RefreshToken}}, testClientID, testClientSecret))
	revoked := postOAuthForm(server.RevocationHandler(), url.Values{"token": {token.AccessToken}}, testClientID, testClientSecret)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revocation status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	accessSignature := server.accessTokens.AccessTokenSignature(context.Background(), token.AccessToken)
	refresh := server.accessTokens.(interface {
		RefreshTokenSignature(context.Context, string) string
	})
	refreshSignature := refresh.RefreshTokenSignature(context.Background(), token.RefreshToken)
	rows, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?),(SELECT active FROM oauth_refresh_tokens WHERE signature=?)`, Args: []any{accessSignature, refreshSignature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) {
		t.Fatalf("revoked token family rows=%#v err=%v", rows.Rows, err)
	}
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "restore-account-consumer", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=NULL WHERE subject=?`, Args: []any{"user-1"}}); err != nil {
		t.Fatal(err)
	}
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token.AccessToken}}, testClientID, testClientSecret))
}

func TestAlreadyIssuedDeviceTokenIntrospectionBecomesInactiveAfterAccountShortening(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-user", time.Now().UTC().Add(time.Hour).UnixMilli())
	store := device.NewStore(db)
	now := time.Now().UTC()
	grant, err := store.Create(context.Background(), testClientID, []string{"goauthy.read"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(context.Background(), grant.UserCode, "device-user", now); err != nil {
		t.Fatal(err)
	}
	token := decodeToken(t, postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}))
	setConsumerExpiryClock(server)
	shortenAccountExpiryAt(t, db, "device-user", consumerExpiryNow)
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token.AccessToken}}, testClientID, testClientSecret))
}

func TestAlreadyIssuedExchangeTokenIntrospectionBecomesInactiveWhenActorExpires(t *testing.T) {
	server := exchangeTestServer(t)
	seedAccountExpiry(t, server.store.db, time.Now().UTC().Add(time.Hour))
	seedAccountExpiryForSubject(t, server.store.db, "actor-2", time.Now().UTC().Add(time.Hour))
	owner := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	exchanged := decodeAccountExpiryResponse(t, postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {owner.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource}}))
	setConsumerExpiryClock(server)
	shortenAccountExpiryAt(t, server.store.db, "actor-2", consumerExpiryNow)
	assertInactive(t, postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {exchanged.AccessToken}}, testClientID, testClientSecret))
	ownerIntrospection := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {owner.AccessToken}}, testClientID, testClientSecret)
	var ownerPayload map[string]any
	if err := json.Unmarshal(ownerIntrospection.Body.Bytes(), &ownerPayload); err != nil || ownerIntrospection.Code != http.StatusOK || ownerPayload["active"] != true {
		t.Fatalf("future owner status=%d payload=%#v err=%v", ownerIntrospection.Code, ownerPayload, err)
	}
}

func TestAlreadyIssuedUserTokenConsumersRejectAfterAccountShortening(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	token := issueUserInfoToken(t, server)
	setConsumerExpiryClock(server)
	shortenAccountExpiryAt(t, db, "user-1", consumerExpiryNow)
	response := httptest.NewRecorder()
	server.UserInfoHandler().ServeHTTP(response, userInfoRequest(http.MethodGet, token, nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo status=%d body=%s", response.Code, response.Body.String())
	}
	if response = forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil)); response.Code != http.StatusUnauthorized {
		t.Fatalf("forward auth status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestForwardAuthLateProfileExpiryClearsIdentityHeaders(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	token := issueUserInfoToken(t, server)
	server.oidc.ForwardAuthEnabled = true
	server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) { return PrincipalClaims{Revision: 1}, nil }
	server.oidc.ResolveForwardAuthPasskeyEnrollment = func(context.Context, string) (bool, error) { return false, nil }
	calls := 0
	server.oidc.ResolveForwardAuthProfile = func(context.Context, string) (ForwardAuthProfile, error) {
		calls++
		if calls == 2 {
			shortenAccountExpiryAt(t, db, "user-1", consumerExpiryNow)
		}
		return ForwardAuthProfile{PreferredUsername: "alice"}, nil
	}
	setConsumerExpiryClock(server)
	if response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil)); response.Code != http.StatusOK {
		t.Fatalf("initial forward auth status=%d headers=%v", response.Code, response.Header())
	}
	request := forwardAuthRequest(http.MethodGet, token, nil)
	response := forwardAuthResponse(server, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("late expiry forward auth status=%d", response.Code)
	}
	for _, header := range managedForwardAuthHeaders {
		if response.Header().Get(header) != "" {
			t.Fatalf("late expiry forwarded %s=%q", header, response.Header().Get(header))
		}
	}
}

func TestAccountExpiryConsumerPositiveNeighborsAndMachineToken(t *testing.T) {
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	nullToken := issueUserInfoToken(t, server)
	if response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, nullToken, nil)); response.Code != http.StatusOK {
		t.Fatalf("nullable account forward auth status=%d", response.Code)
	}
	setConsumerExpiryClock(server)
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "future-account-consumer", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{consumerExpiryNow.Add(time.Hour).UnixMilli(), "user-1"}}); err != nil {
		t.Fatal(err)
	}
	if response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, nullToken, nil)); response.Code != http.StatusOK {
		t.Fatalf("future account forward auth status=%d", response.Code)
	}
	machine := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}}))
	shortenAccountExpiryAt(t, server.store.db, "user-1", consumerExpiryNow)
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {machine.AccessToken}}, testClientID, testClientSecret)
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || response.Code != http.StatusOK || payload["active"] != true {
		t.Fatalf("machine token status=%d payload=%#v err=%v", response.Code, payload, err)
	}
}

func TestValidateTokenAccountsBoundaryAndShapeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		stmt string
		args []any
		want bool
	}{
		{"nullable", `UPDATE identity_users SET user_expires_at_unix_ms=NULL WHERE subject=?`, []any{"user-1"}, true},
		{"future by one millisecond", `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, []any{consumerExpiryNow.UnixMilli() + 1, "user-1"}, true},
		{"now", `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, []any{consumerExpiryNow.UnixMilli(), "user-1"}, false},
		{"zero", `UPDATE identity_users SET user_expires_at_unix_ms=0 WHERE subject=?`, []any{"user-1"}, false},
		{"disabled", `UPDATE identity_users SET disabled=1 WHERE subject=?`, []any{"user-1"}, false},
		{"missing", `DELETE FROM identity_users WHERE subject=?`, []any{"user-1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
			token := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueCode(t, server, strings.Repeat("m", 43))}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("m", 43)}}))
			setConsumerExpiryClock(server)
			if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "validate-account-matrix-" + tc.name, SQL: tc.stmt, Args: tc.args}); err != nil {
				t.Fatal(err)
			}
			signature := server.accessTokens.AccessTokenSignature(context.Background(), token.AccessToken)
			request, err := server.store.GetAccessTokenSession(context.Background(), signature, &fosite.DefaultSession{})
			if err != nil {
				t.Fatal(err)
			}
			got := server.store.validateTokenAccounts(context.Background(), request) == nil
			if got != tc.want {
				t.Fatalf("valid=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestValidateTokenAccountsRejectsExpiredActorAndMalformedActors(t *testing.T) {
	server := exchangeTestServer(t)
	seedAccountExpiry(t, server.store.db, time.Now().UTC().Add(time.Hour))
	seedAccountExpiryForSubject(t, server.store.db, "actor-2", time.Now().UTC().Add(time.Hour))
	owner := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	exchanged := decodeAccountExpiryResponse(t, postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {owner.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource}}))
	setConsumerExpiryClock(server)
	shortenAccountExpiryAt(t, server.store.db, "actor-2", consumerExpiryNow)
	signature := server.accessTokens.AccessTokenSignature(context.Background(), exchanged.AccessToken)
	request, err := server.store.GetAccessTokenSession(context.Background(), signature, &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.validateTokenAccounts(context.Background(), request); err == nil {
		t.Fatal("accepted expired actor")
	}
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "restore-actor-for-shape", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{consumerExpiryNow.UnixMilli() + 1, "actor-2"}}); err != nil {
		t.Fatal(err)
	}
	request.GetSession().(*fosite.DefaultSession).Extra["act"] = map[string]any{"sub": "actor-2"}
	if err := server.store.validateTokenAccounts(context.Background(), request); err != nil {
		t.Fatalf("valid actor rejected: %v", err)
	}
	for name, value := range map[string]any{"string": "actor-2", "nested": map[string]any{"sub": "actor-2", "extra": true}} {
		t.Run(name, func(t *testing.T) {
			session := request.GetSession().(*fosite.DefaultSession)
			session.Extra["act"] = value
			if err := server.store.validateTokenAccounts(context.Background(), request); err == nil {
				t.Fatal("accepted malformed actor")
			}
		})
	}
}

func TestValidateTokenAccountsDistinguishesMachineAndUserClientSubject(t *testing.T) {
	server := exchangeTestServer(t)
	machine := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}}))
	setConsumerExpiryClock(server)
	machineRequest, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), machine.AccessToken), &fosite.DefaultSession{})
	if err != nil || server.store.validateTokenAccounts(context.Background(), machineRequest) != nil {
		t.Fatalf("rejected machine token err=%v", err)
	}
	user := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, testClientID, "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	userRequest, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), user.AccessToken), &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.validateTokenAccounts(context.Background(), userRequest); err != nil {
		t.Fatalf("user subject equal client ID rejected as machine: %v", err)
	}
	userSubject := userRequest.GetSession().GetSubject()
	if userSubject != testClientID {
		t.Fatalf("subject=%q", userSubject)
	}
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "expire-clientid-user", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{consumerExpiryNow.UnixMilli(), testClientID}}); err != nil {
		t.Fatal(err)
	}
	if err := server.store.validateTokenAccounts(context.Background(), userRequest); err == nil {
		t.Fatal("accepted expired user whose subject equals client ID")
	}
	if err := server.store.validateTokenAccounts(context.Background(), machineRequest); err != nil {
		t.Fatalf("machine token became account-bound: %v", err)
	}
}

var consumerExpiryNow = time.Unix(1_700_000_000, 0).UTC()

func setConsumerExpiryClock(server *Server) {
	server.store.now = func() time.Time { return consumerExpiryNow }
}

func shortenAccountExpiryAt(t *testing.T, db *rhiza.DB, subject string, at time.Time) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "shorten-account-consumer-" + subject, SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{at.UnixMilli(), subject}}); err != nil {
		t.Fatal(err)
	}
}

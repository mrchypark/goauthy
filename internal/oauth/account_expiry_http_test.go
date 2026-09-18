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

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type accountExpiryTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func TestAccountExpiryCapsHTTPTokenLifetimes(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	deadline := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	seedAccountExpiry(t, db, deadline)
	code := issueOIDCCode(t, server, strings.Repeat("e", 43), "expiry", oidcTestAuthTime, oidcTestSessionID(0))
	issued := decodeAccountExpiryResponse(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("e", 43)}}))
	assertAccountExpiryToken(t, server, issued, key, deadline)

	refreshed := decodeAccountExpiryResponse(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
	assertAccountExpiryToken(t, server, refreshed, key, deadline)
}

func TestAccountExpirySnapshotShorteningRejectsAndPreservesCode(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	seedAccountExpiry(t, db, time.Now().UTC().Add(10*time.Minute))
	verifier := strings.Repeat("s", 43)
	code := issueOIDCCode(t, server, verifier, "shorten", oidcTestAuthTime, oidcTestSessionID(1))
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "shorten-account-before-issue", SQL: `UPDATE identity_users SET user_expires_at_unix_ms = ? WHERE subject = ?`, Args: []any{time.Now().UTC().Add(5 * time.Minute).UnixMilli(), "user-1"}})
		if err != nil {
			t.Fatalf("expire account: %v", err)
		}
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}
	response := postToken(server, form)
	if response.Code == http.StatusOK {
		t.Fatal("token issued after account expiry snapshot was shortened")
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "restore-account-before-retry", SQL: `UPDATE identity_users SET user_expires_at_unix_ms = ? WHERE subject = ?`, Args: []any{time.Now().UTC().Add(10 * time.Minute).UnixMilli(), "user-1"}}); err != nil {
		t.Fatal(err)
	}
	if retry := postToken(server, form); retry.Code != http.StatusOK {
		t.Fatalf("authorization code was consumed after rejected issuance: status=%d body=%s", retry.Code, retry.Body.String())
	}
}

func TestAccountExpiryNullableNeighborStillIssues(t *testing.T) {
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	seedAccountExpiry(t, db, nil)
	verifier := strings.Repeat("n", 43)
	code := issueOIDCCode(t, server, verifier, "nullable", oidcTestAuthTime, oidcTestSessionID(2))
	if response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}); response.Code != http.StatusOK {
		t.Fatalf("nullable account rejected: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAccountExpiryCapsTokenExchangeToOwnerAndActor(t *testing.T) {
	server := exchangeTestServer(t)
	ownerDeadline := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	actorDeadline := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	seedAccountExpiry(t, server.store.db, ownerDeadline)
	seedAccountExpiryForSubject(t, server.store.db, "actor-2", actorDeadline)
	owner := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	ownerClaims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(context.Background(), owner.AccessToken)
	if err != nil || ownerClaims.ExpiresAt.After(ownerDeadline) {
		t.Fatalf("owner token expiry=%s err=%v deadline=%s", ownerClaims.ExpiresAt, err, ownerDeadline)
	}
	actorClaims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(context.Background(), actor.AccessToken)
	if err != nil || actorClaims.ExpiresAt.After(actorDeadline) {
		t.Fatalf("actor token expiry=%s err=%v deadline=%s", actorClaims.ExpiresAt, err, actorDeadline)
	}
	values := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {owner.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource}}
	exchanged := decodeAccountExpiryResponse(t, postToken(server, values))
	if exchanged.ExpiresIn <= 0 || exchanged.ExpiresIn > 300 {
		t.Fatalf("exchange expires_in=%d, want <= 300", exchanged.ExpiresIn)
	}
	targetClaims, err := server.accessTokens.(*signedAccessTokenStrategy).verify(context.Background(), exchanged.AccessToken)
	if err != nil || targetClaims.ExpiresAt.After(actorDeadline) {
		t.Fatalf("target token expiry=%s err=%v actor deadline=%s", targetClaims.ExpiresAt, err, actorDeadline)
	}
}

func TestAccountExpiryActorSnapshotShorteningRejectsExchange(t *testing.T) {
	server := exchangeTestServer(t)
	seedAccountExpiry(t, server.store.db, time.Now().UTC().Add(10*time.Minute))
	seedAccountExpiryForSubject(t, server.store.db, "actor-2", time.Now().UTC().Add(10*time.Minute))
	owner := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	actor := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "actor-2", "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}))
	before := tokenExchangeAccessCount(t, server)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "shorten-actor-before-exchange", SQL: `UPDATE identity_users SET user_expires_at_unix_ms = ? WHERE subject = ?`, Args: []any{time.Now().UTC().Add(5 * time.Minute).UnixMilli(), "actor-2"}}); err != nil {
			t.Fatalf("shorten actor expiry: %v", err)
		}
	}
	response := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {owner.AccessToken}, "subject_token_type": {accessTokenType}, "actor_token": {actor.AccessToken}, "actor_token_type": {accessTokenType}, "scope": {"goauthy.read"}, "resource": {exchangeResource}})
	if response.Code == http.StatusOK {
		t.Fatal("exchange issued after actor deadline snapshot changed")
	}
	if after := tokenExchangeAccessCount(t, server); after != before {
		t.Fatalf("failed exchange created target row: before=%d after=%d", before, after)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), owner.AccessToken), nil); err != nil {
		t.Fatalf("owner source became unusable: %v", err)
	}
	if _, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), actor.AccessToken), nil); err != nil {
		t.Fatalf("actor source became unusable: %v", err)
	}
}

func TestAccountExpiryCapsDeviceTokens(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	deadline := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	seedDeviceUser(t, db, "device-user", deadline.UnixMilli())
	deviceStore := device.NewStore(db)
	now := time.Now().UTC()
	grant, err := deviceStore.Create(context.Background(), testClientID, []string{"goauthy.read", "offline_access"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Approve(context.Background(), grant.UserCode, "device-user", now); err != nil {
		t.Fatal(err)
	}
	issued := decodeToken(t, postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}))
	accessSignature := server.accessTokens.AccessTokenSignature(context.Background(), issued.AccessToken)
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT expires_at_unix_ms FROM oauth_access_tokens WHERE signature = ?`, Args: []any{accessSignature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || time.UnixMilli(rows.Rows[0][0].(int64)).After(deadline) {
		t.Fatalf("device access expiry rows=%#v err=%v deadline=%s", rows.Rows, err, deadline)
	}
	refresh := server.accessTokens.(interface {
		RefreshTokenSignature(context.Context, string) string
	})
	refreshSignature := refresh.RefreshTokenSignature(context.Background(), issued.RefreshToken)
	rows, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT expires_at_unix_ms FROM oauth_refresh_tokens WHERE signature = ?`, Args: []any{refreshSignature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || time.UnixMilli(rows.Rows[0][0].(int64)).After(deadline) {
		t.Fatalf("device refresh expiry rows=%#v err=%v deadline=%s", rows.Rows, err, deadline)
	}
}

func TestAccountExpiryDeviceSnapshotShorteningPreservesClaim(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-user", time.Now().UTC().Add(10*time.Minute).UnixMilli())
	deviceStore := device.NewStore(db)
	now := time.Now().UTC()
	grant, err := deviceStore.Create(context.Background(), testClientID, []string{"goauthy.read", "offline_access"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Approve(context.Background(), grant.UserCode, "device-user", now); err != nil {
		t.Fatal(err)
	}
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "shorten-device-before-issue", SQL: `UPDATE identity_users SET user_expires_at_unix_ms = ? WHERE subject = ?`, Args: []any{time.Now().UTC().Add(5 * time.Minute).UnixMilli(), "device-user"}}); err != nil {
			t.Fatalf("shorten device account expiry: %v", err)
		}
	}
	response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}})
	if response.Code == http.StatusOK {
		t.Fatal("device token issued after account deadline snapshot changed")
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state, (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_refresh_tokens), (SELECT COUNT(*) FROM oauth_token_requests) FROM oauth_device_grants WHERE device_code_digest = ?`, Args: []any{deviceDigestForTest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) || rows.Rows[0][3] != int64(0) {
		t.Fatalf("failed device issuance consumed claim or minted tokens: rows=%#v err=%v", rows.Rows, err)
	}
}

func seedAccountExpiryForSubject(t *testing.T, db *rhiza.DB, subject string, expires time.Time) {
	t.Helper()
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "seed-account-expiry-http-" + subject, SQL: `INSERT INTO identity_users (subject,username,password_phc,user_expires_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{subject, subject, "phc", expires.UnixMilli()}})
	if err != nil {
		t.Fatal(err)
	}
}

func seedAccountExpiry(t *testing.T, db *rhiza.DB, expires any) {
	t.Helper()
	if deadline, ok := expires.(time.Time); ok {
		expires = deadline.UnixMilli()
	}
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "seed-account-expiry-http", SQL: `INSERT INTO identity_users (subject,username,password_phc,user_expires_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{"user-1", "user-1", "phc", expires}})
	if err != nil {
		t.Fatal(err)
	}
}

func decodeAccountExpiryResponse(t *testing.T, response *httptest.ResponseRecorder) accountExpiryTokenResponse {
	t.Helper()
	var token accountExpiryTokenResponse
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || response.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s err=%v", response.Code, response.Body.String(), err)
	}
	return token
}

func assertAccountExpiryToken(t *testing.T, server *Server, token accountExpiryTokenResponse, key oidc.SigningKey, deadline time.Time) {
	t.Helper()
	if token.AccessToken == "" || token.RefreshToken == "" || token.IDToken == "" || token.ExpiresIn <= 0 || token.ExpiresIn > 600 {
		t.Fatalf("token response exceeds account deadline: %#v", token)
	}
	accessClaims, err := oidc.VerifyAccessToken(token.AccessToken, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, oidcTestIssuer, time.Now().UTC())
	if err != nil || accessClaims.ExpiresAt.After(deadline) {
		t.Fatalf("access token verification/expiry err=%v exp=%s deadline=%s", err, accessClaims.ExpiresAt, deadline)
	}
	if idClaims := verifyOIDCTestToken(t, token.IDToken, key, time.Now().UTC()); idClaims.ExpiresAt.After(deadline) {
		t.Fatalf("ID token exp=%s exceeds deadline=%s", idClaims.ExpiresAt, deadline)
	}
	for name, compact := range map[string]string{"access": token.AccessToken, "id": token.IDToken} {
		payload := jwtPayload(t, compact)
		exp, ok := payload["exp"].(float64)
		if !ok || time.Unix(int64(exp), 0).After(deadline) {
			t.Fatalf("%s exp=%v exceeds deadline %s", name, payload["exp"], deadline)
		}
	}
	accessSignature := server.accessTokens.AccessTokenSignature(context.Background(), token.AccessToken)
	rows, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT expires_at_unix_ms FROM oauth_access_tokens WHERE signature = ?`, Args: []any{accessSignature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || time.UnixMilli(rows.Rows[0][0].(int64)).After(deadline) {
		t.Fatalf("persisted access expiry rows=%#v err=%v deadline=%s", rows.Rows, err, deadline)
	}
	if time.UnixMilli(rows.Rows[0][0].(int64)).Unix() != accessClaims.ExpiresAt.Unix() {
		t.Fatalf("persisted access expiry=%v differs from signed exp=%v", time.UnixMilli(rows.Rows[0][0].(int64)), accessClaims.ExpiresAt)
	}
	refresh, ok := server.accessTokens.(interface {
		RefreshTokenSignature(context.Context, string) string
	})
	if !ok {
		t.Fatal("OAuth strategy does not support refresh tokens")
	}
	refreshSignature := refresh.RefreshTokenSignature(context.Background(), token.RefreshToken)
	rows, err = server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT expires_at_unix_ms FROM oauth_refresh_tokens WHERE signature = ?`, Args: []any{refreshSignature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || time.UnixMilli(rows.Rows[0][0].(int64)).After(deadline) {
		t.Fatalf("persisted refresh expiry rows=%#v err=%v deadline=%s", rows.Rows, err, deadline)
	}
}

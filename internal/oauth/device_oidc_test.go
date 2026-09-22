package oauth

import (
	"context"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeviceOIDCIssuesCurrentGroupsAndRefreshesWithoutBrowserClaims(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	seedDeviceUser(t, db, "device-oidc-user", nil)
	seedDeviceOIDCRevision(t, db, "device-oidc-user", 1)
	principal := PrincipalClaims{Groups: []string{"team/one"}, Revision: 1}
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) { return principal, nil }

	grant, err := device.NewStore(db).Create(context.Background(), testClientID, []string{openidScope, groupsScope, "offline_access"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.NewStore(db).Approve(context.Background(), grant.UserCode, "device-oidc-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	issued := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}))
	claims := verifyOIDCTestToken(t, issued.IDToken, key, time.Now().UTC())
	assertDeviceOIDCClaims(t, claims, issued.AccessToken, "device-oidc-user", []string{"team/one"})

	principal.Groups = []string{"team/two"}
	refreshed := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
	refreshedClaims := verifyOIDCTestToken(t, refreshed.IDToken, key, time.Now().UTC())
	assertDeviceOIDCClaims(t, refreshedClaims, refreshed.AccessToken, "device-oidc-user", []string{"team/two"})
}

func TestDeviceOIDCIsOnceOnlyAndOAuthOnlyRejectsOpenID(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedDeviceUser(t, db, "device-oidc-user", nil)
	store := device.NewStore(db)
	grant, err := store.Create(context.Background(), testClientID, []string{openidScope, "offline_access"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(context.Background(), grant.UserCode, "device-oidc-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	oauthOnly := oauthTestServer(t, db, randomSecret(t))
	if response := postToken(oauthOnly, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}); response.Code == http.StatusOK {
		t.Fatal("OAuth-only device grant accepted openid")
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state, (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_refresh_tokens) FROM oauth_device_grants WHERE device_code_digest=?`, Args: []any{deviceDigestForTest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) {
		t.Fatalf("OAuth-only rejection mutated grant rows=%#v err=%v", rows.Rows, err)
	}

	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	grant, err = store.Create(context.Background(), testClientID, []string{openidScope, "offline_access"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(context.Background(), grant.UserCode, "device-oidc-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}))
	used := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}})
	if used.Code != http.StatusBadRequest || oauthErrorCode(t, used) != "expired_token" {
		t.Fatalf("replayed device response=%d body=%s", used.Code, used.Body.String())
	}
}

func TestDeviceOIDCConfidentialClientSecretPost(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	client, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "device-oidc-post", GrantTypes: []string{DeviceGrantType},
		Scopes:                  []string{openidScope, groupsScope, "offline_access"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientPost, Name: "device oidc post",
	})
	if err != nil {
		t.Fatal(err)
	}
	seedDeviceUser(t, db, "device-oidc-post-user", nil)
	h, err := device.NewHandler(device.NewStore(db), "https://id.example.test", server.AuthenticateDeviceClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"client_id": {client.ClientID}, "client_secret": {client.ClientSecret}, "scope": {openidScope + " " + groupsScope + " offline_access"}}
	request := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("device authorization status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.DeviceCode == "" || created.UserCode == "" {
		t.Fatalf("device authorization response=%s err=%v", response.Body.String(), err)
	}
	if err := device.NewStore(db).Approve(context.Background(), created.UserCode, "device-oidc-post-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	tokenForm := url.Values{"grant_type": {DeviceGrantType}, "device_code": {created.DeviceCode}, "client_id": {client.ClientID}, "client_secret": {client.ClientSecret}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(tokenForm.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(tokenResponse, tokenRequest)
	issued := decodeOIDCToken(t, tokenResponse)
	claims, err := oidc.VerifyIDToken(issued.IDToken, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, oidcTestIssuer, client.ClientID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "device-oidc-post-user" || claims.AuthorizedParty != client.ClientID || claims.AccessTokenHash != oidc.AccessTokenHash(issued.AccessToken) {
		t.Fatal("confidential device ID token claims mismatch")
	}
}

func TestDeviceOIDCPrincipalRevisionRaceLeavesNoArtifacts(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	key := oidcTestKey(t)
	seedDeviceUser(t, db, "device-oidc-user", nil)
	seedDeviceOIDCRevision(t, db, "device-oidc-user", 1)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return key, nil })
	server.oidc.ResolvePrincipal = func(context.Context, string) (PrincipalClaims, error) {
		return PrincipalClaims{Groups: []string{"team/one"}, Revision: 1}, nil
	}
	grant, err := device.NewStore(db).Create(context.Background(), testClientID, []string{openidScope, groupsScope, "offline_access"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.NewStore(db).Approve(context.Background(), grant.UserCode, "device-oidc-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "device-oidc-revision-race", SQL: `UPDATE rbac_principal_versions SET revision=2 WHERE subject=?`, Args: []any{"device-oidc-user"}}); err != nil {
			t.Fatal(err)
		}
	}
	response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}})
	if response.Code == http.StatusOK {
		t.Fatal("principal revision race issued device tokens")
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state, claim_token_digest, (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_refresh_tokens), (SELECT COUNT(*) FROM oauth_token_requests) FROM oauth_device_grants WHERE device_code_digest=?`, Args: []any{deviceDigestForTest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	// Execute was attempted: retain the claim for existing reconciliation rather
	// than releasing it and risking a second mint after an ambiguous commit.
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] == nil || rows.Rows[0][2] != int64(0) || rows.Rows[0][3] != int64(0) || rows.Rows[0][4] != int64(0) {
		t.Fatalf("revision race left artifacts rows=%#v err=%v", rows.Rows, err)
	}
}

func assertDeviceOIDCClaims(t *testing.T, claims oidc.IDTokenClaims, accessToken, subject string, groups []string) {
	t.Helper()
	if claims.Subject != subject || !sameStrings(claims.Audience, []string{testClientID}) || claims.AuthorizedParty != testClientID || claims.AccessTokenHash != oidc.AccessTokenHash(accessToken) || !sameStrings(claims.Groups, groups) || claims.Nonce != "" || !claims.AuthTime.IsZero() || claims.SessionID != "" || len(claims.AuthenticationMethods) != 0 {
		t.Fatalf("unexpected device ID-token claims=%#v", claims)
	}
}

func seedDeviceOIDCRevision(t *testing.T, db *rhiza.DB, subject string, revision int64) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "seed-device-oidc-revision-" + subject, SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,?,0)`, Args: []any{subject, revision}}); err != nil {
		t.Fatal(err)
	}
}

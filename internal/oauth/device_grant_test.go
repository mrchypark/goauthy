package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

func TestDeviceGrantIssuesStoredAccessAndRefreshTokensOnce(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-user", nil)
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
	if issued.AccessToken == "" || issued.RefreshToken == "" || issued.TokenType != "bearer" || issued.Scope != "goauthy.read offline_access" {
		t.Fatalf("unexpected device tokens: %#v", issued)
	}
	request, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), issued.AccessToken), nil)
	if err != nil || request.GetSession().GetSubject() != "device-user" {
		t.Fatalf("stored device session request=%#v err=%v", request, err)
	}
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state FROM oauth_device_grants WHERE device_code_digest = ?`, Args: []any{deviceDigestForTest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("device state rows=%#v err=%v", result.Rows, err)
	}
	if got, ok := result.Rows[0][0].(string); !ok || got != "consumed" {
		t.Fatalf("device state=%#v", result.Rows)
	}

	used := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}})
	if used.Code != http.StatusBadRequest || oauthErrorCode(t, used) != "expired_token" {
		t.Fatalf("used device response=%d body=%s", used.Code, used.Body.String())
	}
}

func TestDeviceGrantConcurrentPollMintsOnce(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-user", nil)
	deviceStore := device.NewStore(db)
	grant, err := deviceStore.Create(context.Background(), testClientID, []string{"goauthy.read"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Approve(context.Background(), grant.UserCode, "device-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses <- postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}).Code
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("device token successes=%d", successes)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("access token rows=%#v err=%v", rows.Rows, err)
	}
}

func TestAuthorizeDeviceClientRejectsOpenIDAndUnauthorizedScopes(t *testing.T) {
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	if err := server.AuthorizeDeviceClient(context.Background(), testClientID, []string{"goauthy.read"}); err != nil {
		t.Fatalf("authorize device client: %v", err)
	}
	for _, scopes := range [][]string{{"openid"}, {"groups"}, {"unknown"}} {
		if err := server.AuthorizeDeviceClient(context.Background(), testClientID, scopes); err == nil {
			t.Fatalf("accepted device scopes %#v", scopes)
		}
	}
}

func TestDynamicDeviceClientAuthorizationHTTP(t *testing.T) {
	ctx := context.Background()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	registered, err := server.store.dynamicClients.Create(ctx, dcr.CreateRequest{
		ClientID:                "dynamic-device-only",
		GrantTypes:              []string{DeviceGrantType},
		Scopes:                  []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone,
		Name:                    "Dynamic device client",
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceHandler, err := device.NewHandler(device.NewStore(db), "https://id.example.test", server.AuthenticateDeviceClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	postDevice := func(scopes string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(url.Values{
			"client_id": {registered.ClientID},
			"scope":     {scopes},
		}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		deviceHandler.ServeHTTP(response, request)
		return response
	}

	accepted := postDevice("goauthy.read")
	if accepted.Code != http.StatusOK {
		t.Fatalf("dynamic device authorization status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	var grant struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(accepted.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.DeviceCode == "" || grant.UserCode == "" {
		t.Fatalf("dynamic device authorization response=%s", accepted.Body.String())
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT client_id, scopes_json FROM oauth_device_grants WHERE device_code_digest = ?`,
		Args: []any{deviceDigestForTest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 2 || rows.Rows[0][0] != registered.ClientID || rows.Rows[0][1] != `["goauthy.read"]` {
		t.Fatalf("persisted dynamic device grant rows=%#v err=%v", rows.Rows, err)
	}

	rejected := postDevice("offline_access")
	if rejected.Code != http.StatusBadRequest || oauthErrorCode(t, rejected) != "invalid_client" {
		t.Fatalf("unauthorized dynamic device scope status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	count, err := db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM oauth_device_grants`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(count.Rows) != 1 || count.Rows[0][0] != int64(1) {
		t.Fatalf("unauthorized dynamic device scope created a grant rows=%#v err=%v", count.Rows, err)
	}
}

func TestDeviceGrantRejectsGroupsBeforeTokenMutation(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-user", nil)
	deviceStore := device.NewStore(db)
	grant, err := deviceStore.Create(context.Background(), testClientID, []string{groupsScope}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Approve(context.Background(), grant.UserCode, "device-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}})
	if response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_scope" {
		t.Fatalf("groups response=%d body=%s", response.Code, response.Body.String())
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state,claim_token_digest,(SELECT COUNT(*) FROM oauth_access_tokens),(SELECT COUNT(*) FROM oauth_refresh_tokens) FROM oauth_device_grants WHERE device_code_digest = ?`, Args: []any{deviceDigestForTest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 4 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] != nil || rows.Rows[0][2] != int64(0) || rows.Rows[0][3] != int64(0) {
		t.Fatalf("groups rejection mutated device/token state rows=%#v err=%v", rows.Rows, err)
	}
}

func TestDeviceGrantRFCStateErrorsAndValidationFailureLeavesNoArtifacts(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-user", nil)
	deviceStore := device.NewStore(db)
	now := time.Now().UTC()
	pending, err := deviceStore.Create(context.Background(), testClientID, []string{"goauthy.read"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {pending.DeviceCode}}); response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "authorization_pending" {
		t.Fatalf("pending response=%d body=%s", response.Code, response.Body.String())
	}
	if response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {pending.DeviceCode}}); response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "slow_down" {
		t.Fatalf("slow_down response=%d body=%s", response.Code, response.Body.String())
	}
	denied, err := deviceStore.Create(context.Background(), testClientID, []string{"goauthy.read"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Deny(context.Background(), denied.UserCode, now); err != nil {
		t.Fatal(err)
	}
	if response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {denied.DeviceCode}}); response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "access_denied" {
		t.Fatalf("denied response=%d body=%s", response.Code, response.Body.String())
	}
	if response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {"unknown"}}); response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "expired_token" {
		t.Fatalf("expired response=%d body=%s", response.Code, response.Body.String())
	}

	invalid, err := deviceStore.Create(context.Background(), testClientID, []string{"not-allowed"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Approve(context.Background(), invalid.UserCode, "device-user", now); err != nil {
		t.Fatal(err)
	}
	if response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {invalid.DeviceCode}}); response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_scope" {
		t.Fatalf("invalid scope response=%d body=%s", response.Code, response.Body.String())
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state, claim_token_digest FROM oauth_device_grants WHERE device_code_digest = ?`, Args: []any{deviceDigestForTest(invalid.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] != nil {
		t.Fatalf("failed claim was not released rows=%#v err=%v", rows.Rows, err)
	}
	count, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(count.Rows) != 1 || count.Rows[0][0] != int64(0) {
		t.Fatalf("failed issuance left access tokens rows=%#v err=%v", count.Rows, err)
	}
}

func TestDeviceTransactionDoesNotMintAfterGrantExpiry(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-user", nil)
	deviceCode, claimToken := "expired-device-code", "expired-device-claim"
	past := time.Unix(1, 0).UTC()
	future := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "expired-device-grant",
		SQL: `INSERT INTO oauth_device_grants
			(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,claim_token_digest,claim_until_unix_ms,created_at_unix_ms)
			VALUES (?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?)`,
		Args: []any{deviceCodeDigest(deviceCode), deviceCodeDigest("expired-user-code"), testClientID, `["goauthy.read","offline_access"]`, "device-user", past.UnixMilli(), int64(5), past.UnixMilli(), deviceCodeDigest(claimToken), future.UnixMilli(), past.UnixMilli()},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := &fosite.DefaultSession{Subject: "device-user", Username: "device-user"}
	session.SetExpiresAt(fosite.AccessToken, future)
	session.SetExpiresAt(fosite.RefreshToken, future)
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt, request.Session = "expired-device-request", server.store.client, past, session
	request.SetRequestedScopes(fosite.Arguments{"goauthy.read", "offline_access"})
	request.GrantScope("goauthy.read")
	request.GrantScope("offline_access")
	txCtx, err := server.store.BeginDeviceTX(context.Background(), deviceCode, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	_, accessSignature, err := server.accessTokens.GenerateAccessToken(txCtx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.CreateAccessTokenSession(txCtx, accessSignature, request); err != nil {
		t.Fatal(err)
	}
	refreshTokens, ok := server.accessTokens.(oauth2.RefreshTokenStrategy)
	if !ok {
		t.Fatal("OAuth strategy does not support refresh tokens")
	}
	_, refreshSignature, err := refreshTokens.GenerateRefreshToken(txCtx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.CreateRefreshTokenSession(txCtx, refreshSignature, accessSignature, request); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("commit error=%v, want serialization failure", err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state, (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_token_requests), (SELECT COUNT(*) FROM oauth_refresh_tokens) FROM oauth_device_grants WHERE device_code_digest = ?`, Args: []any{deviceCodeDigest(deviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 4 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) || rows.Rows[0][3] != int64(0) {
		t.Fatalf("expired transaction rows=%#v err=%v", rows.Rows, err)
	}
}

func seedDeviceUser(t *testing.T, db *rhiza.DB, subject string, expires any) {
	t.Helper()
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "seed-device-user-" + subject,
		SQL:       `INSERT INTO identity_users (subject,username,password_phc,user_expires_at_unix_ms) VALUES (?, ?, ?, ?)`,
		Args:      []any{subject, subject, "phc", expires},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func oauthErrorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Error
}

func deviceDigestForTest(value string) string { return deviceCodeDigest(value) }

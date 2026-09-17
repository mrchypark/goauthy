package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDynamicDPoPPolicyOptionalBearerAndRequiredMissingProof(t *testing.T) {
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	optional, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-policy-optional", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "optional",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response := postDynamicPolicyToken(server, optional.ClientID, optional.ClientSecret, url.Values{"grant_type": {"client_credentials"}}); response.Code != http.StatusOK {
		t.Fatalf("optional bearer status=%d", response.Code)
	}
	required, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-policy-required", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "required", DPoPBoundAccessTokens: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response := postDynamicPolicyToken(server, required.ClientID, required.ClientSecret, url.Values{"grant_type": {"client_credentials"}}); response.Code != http.StatusBadRequest || tokenError(t, response) != "invalid_request" {
		t.Fatalf("required dynamic client status=%d", response.Code)
	}
}

func TestDynamicDPoPPolicyFalseToTrueClientCredentialsLeavesNoArtifact(t *testing.T) {
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	client, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-policy-race", GrantTypes: []string{"client_credentials"}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "race",
	})
	if err != nil {
		t.Fatal(err)
	}
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "dpop-policy-race-enable", SQL: `UPDATE dynamic_oauth_clients SET dpop_bound_access_tokens=1 WHERE client_id=?`, Args: []any{client.ClientID}}); err != nil {
			t.Fatal(err)
		}
	}
	if response := postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, url.Values{"grant_type": {"client_credentials"}}); response.Code == http.StatusOK {
		t.Fatal("policy race issued bearer token")
	}
	assertClientCredentialsTokenRows(t, server.store.db, 0)
}

func TestDynamicDPoPPolicyRequiredDeviceMissingProofLeavesGrantUnclaimed(t *testing.T) {
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	client, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-policy-device", GrantTypes: []string{DeviceGrantType}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "device", DPoPBoundAccessTokens: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	seedDeviceUser(t, server.store.db, "dpop-policy-device-user", nil)
	grant, err := device.NewStore(server.store.db).Create(context.Background(), client.ClientID, []string{"goauthy.read"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.NewStore(server.store.db).Approve(context.Background(), grant.UserCode, "dpop-policy-device-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	response := postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}})
	if response.Code == http.StatusOK {
		t.Fatal("required device client accepted missing proof")
	}
	assertDeviceDPoPState(t, server.store.db, grant.DeviceCode, "approved", false)
}

func TestDynamicDPoPPolicyFalseToTrueAuthorizationCodeAndRefreshRemainUsable(t *testing.T) {
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	client, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-policy-code", RedirectURIs: []string{"https://rp.example.test/callback"},
		GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
		Scopes: []string{"goauthy.read", "offline_access"}, DefaultScopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "code",
	})
	if err != nil {
		t.Fatal(err)
	}
	seedOAuthUser(t, server.store.db, "dpop-policy-code-user")
	verifier := strings.Repeat("p", 43)
	digest := sha256.Sum256([]byte(verifier))
	redirectURI := "https://rp.example.test/callback"
	values := url.Values{"response_type": {"code"}, "client_id": {client.ClientID}, "redirect_uri": {redirectURI}, "state": {strings.Repeat("s", 32)}, "scope": {"goauthy.read offline_access"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	server.WriteAuthorization(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "dpop-policy-code-user", []string{"goauthy.read", "offline_access"})
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization did not produce code status=%d", w.Code)
	}
	code := location.Query().Get("code")
	setDynamicDPoPPolicy(t, server, client.ClientID, false)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		setDynamicDPoPPolicy(t, server, client.ClientID, true)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	if response := postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, form); response.Code == http.StatusOK {
		t.Fatal("authorization-code policy race issued bearer token")
	}
	assertRBACTokenRows(t, server, 0, 0, 0)
	setDynamicDPoPPolicy(t, server, client.ClientID, false)
	issued := decodeToken(t, postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, form))
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatal("authorization-code retry did not issue access and refresh tokens")
	}
	assertRBACTokenRows(t, server, 1, 1, 1)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		setDynamicDPoPPolicy(t, server, client.ClientID, true)
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}
	if response := postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, refresh); response.Code == http.StatusOK {
		t.Fatal("refresh policy race issued bearer token")
	}
	assertRBACTokenRows(t, server, 1, 1, 1)
	setDynamicDPoPPolicy(t, server, client.ClientID, false)
	if response := postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, refresh); response.Code != http.StatusOK {
		t.Fatalf("refresh retry status=%d", response.Code)
	}
	assertRBACTokenRows(t, server, 1, 2, 1)
}

func TestDynamicDPoPPolicyFalseToTrueDeviceGrantRemainsRetryable(t *testing.T) {
	server := userInfoTestServer(t, oauthTestDB(t), nil)
	client, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID: "dpop-policy-device-race", GrantTypes: []string{DeviceGrantType}, Scopes: []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic, Name: "device-race",
	})
	if err != nil {
		t.Fatal(err)
	}
	seedDeviceUser(t, server.store.db, "dpop-policy-device-race-user", nil)
	grant, err := device.NewStore(server.store.db).Create(context.Background(), client.ClientID, []string{"goauthy.read"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.NewStore(server.store.db).Approve(context.Background(), grant.UserCode, "dpop-policy-device-race-user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		setDynamicDPoPPolicy(t, server, client.ClientID, true)
	}
	form := url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}
	if response := postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, form); response.Code == http.StatusOK {
		t.Fatal("device policy race issued bearer token")
	}
	rows, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state FROM oauth_device_grants WHERE device_code_digest=?`, Args: []any{deviceDigestForTest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] == "consumed" {
		t.Fatalf("device policy race consumed grant rows=%#v err=%v", rows.Rows, err)
	}
	assertClientCredentialsTokenRows(t, server.store.db, 0)
}

var dpopPolicyChanges atomic.Int64

func setDynamicDPoPPolicy(t *testing.T, server *Server, clientID string, required bool) {
	t.Helper()
	value := int64(0)
	if required {
		value = 1
	}
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("dpop-policy-set-%s-%d", clientID, dpopPolicyChanges.Add(1)), SQL: `UPDATE dynamic_oauth_clients SET dpop_bound_access_tokens=? WHERE client_id=?`, Args: []any{value, clientID}}); err != nil {
		t.Fatal(err)
	}
}

func postDynamicPolicyToken(server *Server, clientID, secret string, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, secret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	return response
}

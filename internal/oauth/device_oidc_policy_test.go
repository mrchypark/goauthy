package oauth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeviceOIDCGroupPolicyAllowsAndDenies(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		groups  []string
		allowed bool
	}{
		{name: "allowed", groups: []string{"team/device"}, allowed: true},
		{name: "denied", groups: []string{"other"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &PrincipalClaims{Groups: test.groups, Revision: 1}
			server := clientGroupPolicyServer(t, state)
			deviceCode := grantDeviceOIDC(t, server, "user-1")
			response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {deviceCode}})
			if test.allowed {
				issued := decodeOIDCToken(t, response)
				claims := verifyOIDCTestToken(t, issued.IDToken, oidcTestKey(t), time.Now().UTC())
				assertDeviceOIDCClaims(t, claims, issued.AccessToken, "user-1", test.groups)
				return
			}
			if (response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest) || oauthErrorCode(t, response) != "access_denied" {
				t.Fatalf("denied response=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestDeviceOIDCGroupPolicyRevisionRaceLeavesNoTokenArtifacts(t *testing.T) {
	t.Parallel()
	state := &PrincipalClaims{Groups: []string{"team/device"}, Revision: 1}
	server := clientGroupPolicyServer(t, state)
	deviceCode := grantDeviceOIDC(t, server, "user-1")
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{
			RequestID: "device-group-policy-race",
			SQL:       `UPDATE bootstrap_client_login_restrictions SET revision=2 WHERE client_id=?`,
			Args:      []any{testClientID},
		}); err != nil {
			t.Fatal(err)
		}
	}
	response := postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {deviceCode}})
	if response.Code == http.StatusOK {
		t.Fatal("group policy revision race issued device tokens")
	}
	rows, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{
		SQL:  `SELECT state, claim_token_digest, (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_refresh_tokens), (SELECT COUNT(*) FROM oauth_token_requests) FROM oauth_device_grants WHERE device_code_digest=?`,
		Args: []any{deviceDigestForTest(deviceCode)}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "approved" || rows.Rows[0][1] == nil || rows.Rows[0][2] != int64(0) || rows.Rows[0][3] != int64(0) || rows.Rows[0][4] != int64(0) {
		t.Fatalf("group policy revision race left artifacts rows=%#v err=%v", rows.Rows, err)
	}
}

func grantDeviceOIDC(t *testing.T, server *Server, subject string) string {
	t.Helper()
	grant, err := device.NewStore(server.store.db).Create(context.Background(), testClientID, []string{openidScope, groupsScope, "offline_access"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.NewStore(server.store.db).Approve(context.Background(), grant.UserCode, subject, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return grant.DeviceCode
}

package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestNonOIDCAuthorizationBindsBrowserSession(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	code := issueNonOIDCCode(t, server, strings.Repeat("b", 43))
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT request_json FROM oauth_authorize_codes WHERE signature=?`, Args: []any{server.authorizeCodes.AuthorizeCodeSignature(context.Background(), code)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("bound authorization row=%#v err=%v", result.Rows, err)
	}
	var persisted struct {
		Extra map[string]any `json:"extra"`
	}
	if err := json.Unmarshal([]byte(result.Rows[0][0].(string)), &persisted); err != nil || persisted.Extra[oidcSessionIDExtra] != oidcTestSessionID(11) {
		t.Fatalf("session binding=%+v err=%v", persisted, err)
	}
	pkce, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_pkce_requests WHERE signature=?`, Args: []any{server.authorizeCodes.AuthorizeCodeSignature(context.Background(), code)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(pkce.Rows) != 1 || pkce.Rows[0][0] != int64(1) {
		t.Fatalf("PKCE state=%+v err=%v", pkce, err)
	}
	response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("b", 43)}})
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"id_token"`) {
		t.Fatalf("non-OIDC exchange status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestNonOIDCAuthorizationRejectsInvalidBrowserSessionBinding(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *rhiza.DB, string)
	}{
		{"missing", func(*testing.T, *rhiza.DB, string) {}},
		{"revoked", func(t *testing.T, db *rhiza.DB, sid string) {
			updateBrowserSession(t, db, sid, "revoked_at_unix_ms", 1)
		}},
		{"expired", func(t *testing.T, db *rhiza.DB, sid string) {
			updateBrowserSession(t, db, sid, "expires_at_unix_ms", 1)
		}},
		{"other-subject", func(t *testing.T, db *rhiza.DB, sid string) { updateBrowserSession(t, db, sid, "subject", "other") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
			seedOAuthUser(t, db, "user-1")
			sid := oidcTestSessionID(byte(len(tc.name) + 20))
			if tc.name != "missing" {
				ensureOIDCTestBrowserSession(t, server, sid)
				tc.setup(t, db, sid)
			}
			values := oidcAuthorizationValues(strings.Repeat("x", 43), "")
			values.Set("scope", "goauthy.read offline_access")
			values.Del("nonce")
			response := httptest.NewRecorder()
			server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read", "offline_access"}, oidcTestAuthTime, sid, oidcAuthMethodPwd)
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil || location.Query().Get("code") != "" || location.Query().Get("error") == "" {
				t.Fatalf("invalid session response status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
			}
			assertNoAuthorizationState(t, db)
		})
	}
}

func updateBrowserSession(t *testing.T, db *rhiza.DB, sid, column string, value any) {
	t.Helper()
	if column != "revoked_at_unix_ms" && column != "expires_at_unix_ms" && column != "subject" {
		t.Fatal("invalid test column")
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "bind-session-" + column + sid[:8], SQL: `UPDATE browser_sessions SET ` + column + `=? WHERE token_digest=?`, Args: []any{value, sid}}); err != nil {
		t.Fatal(err)
	}
}

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDynamicAuthorizationCodeLogoutURIUsesCurrentMetadataDuringExchange(t *testing.T) {
	for _, test := range []struct {
		name    string
		current string
	}{
		{name: "updated", current: "https://rp.example.test/updated"},
		{name: "removed", current: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) {
				return oidcTestKey(t), nil
			})
			client, err := server.store.dynamicClients.Create(t.Context(), dcr.CreateRequest{
				ClientID:                "dynamic-code-logout-race",
				RedirectURIs:            []string{"https://rp.example.test/callback"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				Scopes:                  []string{"openid", "goauthy.read", "offline_access"},
				DefaultScopes:           []string{"openid", "goauthy.read", "offline_access"},
				TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone,
				Name:                    "Dynamic code logout race",
				BackchannelLogoutURI:    "https://rp.example.test/original",
			})
			if err != nil {
				t.Fatal(err)
			}
			seedOAuthUser(t, db, "user-1")
			sid := oidcTestSessionID(61)
			ensureOIDCTestBrowserSession(t, server, sid)
			verifier := strings.Repeat("d", 43)
			digest := sha256.Sum256([]byte(verifier))
			values := url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ClientID},
				"redirect_uri":          {"https://rp.example.test/callback"},
				"scope":                 {"openid goauthy.read offline_access"},
				"state":                 {strings.Repeat("s", 32)},
				"nonce":                 {"dynamic-code-logout-race"},
				"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
				"code_challenge_method": {"S256"},
			}
			issued := httptest.NewRecorder()
			server.CompleteAuthorizationWithSession(issued, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"openid", "goauthy.read", "offline_access"}, oidcTestAuthTime, sid, oidcAuthMethodPwd)
			location, err := url.Parse(issued.Header().Get("Location"))
			if err != nil || location.Query().Get("code") == "" {
				t.Fatalf("authorization status=%d location=%q err=%v", issued.Code, issued.Header().Get("Location"), err)
			}

			// Change metadata after the token endpoint client snapshot, before the
			// subject and SID associations are inserted.
			currentSQL := "NULL"
			if test.current != "" {
				currentSQL = "'" + strings.ReplaceAll(test.current, "'", "''") + "'"
			}
			triggerSQL := `CREATE TRIGGER update_code_logout_uri AFTER INSERT ON oauth_access_tokens BEGIN UPDATE dynamic_oauth_clients SET backchannel_logout_uri=` + currentSQL + ` WHERE client_id='dynamic-code-logout-race'; END`
			if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "dynamic-code-logout-uri-race-" + test.name, SQL: triggerSQL}); err != nil {
				t.Fatal(err)
			}

			tokenRequest := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {client.ClientID},
				"code":          {location.Query().Get("code")},
				"redirect_uri":  {"https://rp.example.test/callback"},
				"code_verifier": {verifier},
			}.Encode()))
			tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tokenResponse := httptest.NewRecorder()
			server.TokenHandler().ServeHTTP(tokenResponse, tokenRequest)
			if tokenResponse.Code != http.StatusOK {
				t.Fatalf("token status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
			}

			userAssociation, err := db.Query(t.Context(), rhiza.QueryRequest{
				SQL:  `SELECT subject,client_id,logout_uri FROM oidc_user_clients WHERE subject=? AND client_id=?`,
				Args: []any{"user-1", client.ClientID}, Consistency: rhiza.ConsistencyLinearizable,
			})
			if err != nil || len(userAssociation.Rows) != 1 || len(userAssociation.Rows[0]) != 3 || userAssociation.Rows[0][0] != "user-1" || userAssociation.Rows[0][1] != client.ClientID || userAssociation.Rows[0][2] != test.current {
				t.Fatalf("subject association=%#v err=%v want URI=%q", userAssociation.Rows, err, test.current)
			}
			sidAssociation, err := db.Query(t.Context(), rhiza.QueryRequest{
				SQL:  `SELECT sid,client_id,logout_uri FROM oidc_session_clients WHERE sid=? AND client_id=?`,
				Args: []any{sid, client.ClientID}, Consistency: rhiza.ConsistencyLinearizable,
			})
			if err != nil || len(sidAssociation.Rows) != 1 || len(sidAssociation.Rows[0]) != 3 || sidAssociation.Rows[0][0] != sid || sidAssociation.Rows[0][1] != client.ClientID || sidAssociation.Rows[0][2] != test.current {
				t.Fatalf("SID association=%#v err=%v want URI=%q", sidAssociation.Rows, err, test.current)
			}
		})
	}
}

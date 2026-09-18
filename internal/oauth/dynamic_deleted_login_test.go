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

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestDeletedDynamicClientCannotRecreateLoginLogoutAssociations(t *testing.T) {
	for _, test := range []struct {
		name string
		id   string
		code bool
	}{
		{name: "password", id: "password"},
		{name: "authorization code", id: "code", code: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := oauthTestDB(t)
			users, err := identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			phc, err := credential.Hash([]byte("correct password"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := users.BootstrapUser(t.Context(), "user-1", "alice", phc); err != nil {
				t.Fatal(err)
			}
			server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
				Issuer:          oidcTestIssuer,
				PasswordUsers:   users,
				ValidateSubject: users.ValidateSubject,
				LoadSigningKey:  func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			request := dcr.CreateRequest{
				ClientID:                "deleted-dynamic-login-" + test.id,
				TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic,
				Name:                    "Deleted dynamic login",
				BackchannelLogoutURI:    "https://rp.example.test/logout",
			}
			if test.code {
				request.TokenEndpointAuthMethod = dcr.TokenEndpointAuthNone
				request.RedirectURIs = []string{"https://rp.example.test/callback"}
				request.GrantTypes = []string{"authorization_code"}
				request.ResponseTypes = []string{"code"}
				request.Scopes = []string{"openid", "goauthy.read", "offline_access"}
			} else {
				request.GrantTypes = []string{"password"}
				request.Scopes = []string{"profile"}
				request.DefaultScopes = []string{"profile"}
			}
			client, err := server.store.dynamicClients.Create(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			// Reuse the dynamic-client DPoP policy fence used by the stale-client tests.
			setDynamicDPoPPolicy(t, server, client.ClientID, false)

			var form url.Values
			var subject, sid string
			if test.code {
				subject, sid = "user-1", oidcTestSessionID(73)
				ensureOIDCTestBrowserSession(t, server, sid)
				verifier := strings.Repeat("c", 43)
				digest := sha256.Sum256([]byte(verifier))
				values := url.Values{
					"response_type":         {"code"},
					"client_id":             {client.ClientID},
					"redirect_uri":          {"https://rp.example.test/callback"},
					"scope":                 {"openid goauthy.read offline_access"},
					"state":                 {strings.Repeat("s", 32)},
					"nonce":                 {"deleted-dynamic-login"},
					"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
					"code_challenge_method": {"S256"},
				}
				issued := httptest.NewRecorder()
				server.CompleteAuthorizationWithSession(issued, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), subject, []string{"openid", "goauthy.read", "offline_access"}, oidcTestAuthTime, sid, oidcAuthMethodPwd)
				location, err := url.Parse(issued.Header().Get("Location"))
				if err != nil || location.Query().Get("code") == "" {
					t.Fatalf("authorization status=%d location=%q err=%v", issued.Code, issued.Header().Get("Location"), err)
				}
				form = url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {"https://rp.example.test/callback"}, "code_verifier": {verifier}}
			} else {
				subject = "user-1"
				form = url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}}
			}

			server.beforeTokenIssue = func() {
				server.beforeTokenIssue = nil
				if err := server.store.dynamicClients.DeleteRegistration(t.Context(), client.ClientID, client.RegistrationAccessToken); err != nil {
					t.Fatal(err)
				}
			}
			response := postDynamicPolicyToken(server, client.ClientID, client.ClientSecret, form)
			if response.Code == http.StatusOK {
				t.Fatal("deleted dynamic client issued tokens")
			}

			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT
				(SELECT COUNT(*) FROM dynamic_oauth_clients WHERE client_id=?),
				(SELECT COUNT(*) FROM oidc_user_clients WHERE subject=? AND client_id=?),
				(SELECT COUNT(*) FROM oidc_session_clients WHERE sid=? AND client_id=?)`, Args: []any{client.ClientID, subject, client.ClientID, sid, client.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 3 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) {
				t.Fatalf("deleted dynamic client logout associations recreated: rows=%#v err=%v", rows.Rows, err)
			}
		})
	}
}

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

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestManagedLogoutURIUpdateRaceRejectsStaleTokenIssuance(t *testing.T) {
	for _, grant := range []string{"authorization code", "password"} {
		t.Run(grant, func(t *testing.T) {
			db := oauthTestDB(t)
			users, err := identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			passwordHash, err := credential.Hash([]byte("correct password"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := users.BootstrapUser(t.Context(), "user-1", "alice", passwordHash); err != nil {
				t.Fatal(err)
			}

			managed := clients.NewStore(db, &oidc.Keyring{})
			guard := func() (string, []any) { return "1", nil }
			originalURI := "https://managed.example.test/original"
			client, err := managed.CreateWithGuard(t.Context(), clients.NewRequest{
				ID:                   "managed-logout-uri-race",
				BackchannelLogoutURI: &originalURI,
				RedirectURIs:         []string{testRedirectURI},
				Scopes:               []string{"openid", "goauthy.read", "profile", "offline_access"},
				DefaultScopes:        []string{"openid", "goauthy.read", "profile", "offline_access"},
				GrantTypes:           []string{"authorization_code", "password", "refresh_token"},
			}, guard)
			if err != nil {
				t.Fatal(err)
			}

			server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
				Issuer:          oidcTestIssuer,
				PasswordUsers:   users,
				ManagedClients:  managed,
				ValidateSubject: users.ValidateSubject,
				LoadSigningKey:  func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
			})
			if err != nil {
				t.Fatal(err)
			}

			form := url.Values{}
			sid := ""
			if grant == "authorization code" {
				verifier := strings.Repeat("m", 43)
				digest := sha256.Sum256([]byte(verifier))
				sid = oidcTestSessionID(82)
				ensureOIDCTestBrowserSession(t, server, sid)
				values := url.Values{
					"response_type":         {"code"},
					"client_id":             {client.ID},
					"redirect_uri":          {testRedirectURI},
					"scope":                 {"openid goauthy.read offline_access"},
					"state":                 {strings.Repeat("s", 32)},
					"nonce":                 {"managed-logout-uri-race"},
					"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
					"code_challenge_method": {"S256"},
				}
				issued := httptest.NewRecorder()
				server.CompleteAuthorizationWithSession(issued, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"openid", "goauthy.read", "offline_access"}, oidcTestAuthTime, sid, oidcAuthMethodPwd)
				location, err := url.Parse(issued.Header().Get("Location"))
				if err != nil || location.Query().Get("code") == "" {
					t.Fatalf("authorization status=%d location=%q err=%v", issued.Code, issued.Header().Get("Location"), err)
				}
				form = url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}
			} else {
				form = url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"correct password"}}
			}

			updatedURI := "https://managed.example.test/updated"
			updated := false
			server.beforeTokenIssue = func() {
				server.beforeTokenIssue = nil
				var err error
				client, err = managed.UpdateWithGuard(t.Context(), client.ID, client.Revision, clients.UpdateRequest{
					BackchannelLogoutURI: &updatedURI,
					Confidential:         client.Confidential,
					Enabled:              true,
					RedirectURIs:         client.RedirectURIs,
					Scopes:               client.Scopes,
					DefaultScopes:        client.DefaultScopes,
					GrantTypes:           client.GrantTypes,
					Audiences:            client.Audiences,
					DefaultAudiences:     client.DefaultAudiences,
				}, guard)
				if err != nil {
					t.Fatal(err)
				}
				updated = true
			}

			form.Set("client_id", client.ID)
			request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			server.TokenHandler().ServeHTTP(response, request)
			if !updated {
				t.Fatal("token issuance did not reach managed metadata update hook")
			}
			if response.Code < http.StatusBadRequest || strings.Contains(response.Body.String(), "access_token") {
				t.Fatalf("stale managed metadata issued token: status=%d", response.Code)
			}

			rows, err := db.Query(t.Context(), rhiza.QueryRequest{
				SQL: `SELECT
					(SELECT COUNT(*) FROM oauth_access_tokens),
					(SELECT COUNT(*) FROM oauth_refresh_tokens),
					(SELECT COUNT(*) FROM oauth_token_requests),
					(SELECT COUNT(*) FROM oidc_user_clients WHERE subject=? AND client_id=?),
					(SELECT COUNT(*) FROM oidc_session_clients WHERE sid=? AND client_id=?)`,
				Args: []any{"user-1", client.ID, sid, client.ID}, Consistency: rhiza.ConsistencyLinearizable,
			})
			if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 5 {
				t.Fatalf("stale managed metadata artifacts query rows=%#v err=%v", rows.Rows, err)
			}
			for _, count := range rows.Rows[0] {
				if count != int64(0) {
					t.Fatalf("stale managed metadata left token or logout artifacts: rows=%#v", rows.Rows)
				}
			}
		})
	}
}

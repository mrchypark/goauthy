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
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

const resourceAuthorizationAudience = "https://resource.example.test/api"
const wrongResourceAuthorizationAudience = "https://other-resource.example.test/api"

func resourceAuthorizationServer(t *testing.T, db *rhiza.DB, secret []byte) *Server {
	t.Helper()
	server, err := NewServerWithResourceIndicators(context.Background(), db, secret, testClientID, testClientSecret, testRedirectURI, []string{resourceAuthorizationAudience, wrongResourceAuthorizationAudience})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func issueResourceToken(t *testing.T, server *Server, scope string) tokenResponse {
	return issueResourceTokenForAudience(t, server, scope, resourceAuthorizationAudience)
}

func issueResourceTokenForAudience(t *testing.T, server *Server, scope, audience string) tokenResponse {
	t.Helper()
	server.store.client.(*fosite.DefaultClient).Scopes = append(server.store.client.(*fosite.DefaultClient).Scopes, scope)
	seedOAuthUser(t, server.store.db, "resource-user")
	verifier := strings.Repeat("r", 43)
	codeChallenge := pkceChallenge(verifier)
	values := url.Values{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "scope": {scope}, "state": {strings.Repeat("s", 32)}, "code_challenge": {codeChallenge}, "code_challenge_method": {"S256"}}
	if audience != "" {
		values.Set("resource", audience)
	}
	w := httptest.NewRecorder()
	server.WriteAuthorization(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "resource-user", []string{scope})
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%s", w.Code, w.Header().Get("Location"))
	}
	return decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
}

func pkceChallenge(verifier string) string {
	return base64RawSHA256(verifier)
}

func base64RawSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestAuthorizeUserResourceValidatesHumanBearerAndAtomicGuard(t *testing.T) {
	db := oauthTestDB(t)
	server := resourceAuthorizationServer(t, db, randomSecret(t))
	token := issueResourceToken(t, server, "goauthy.connections.read")
	r := httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	subject, authority, err := server.AuthorizeUserResource(r, "goauthy.connections.read", resourceAuthorizationAudience)
	if err != nil || subject != "resource-user" || authority == nil {
		t.Fatalf("authorize subject=%q err=%v", subject, err)
	}
	guard, args := authority()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("guard rows=%#v err=%v", rows.Rows, err)
	}
	originalClock := server.store.now
	expiredAt := originalClock().UTC().Add(2 * time.Hour)
	server.store.now = func() time.Time { return expiredAt }
	rows, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: authorityArgs(authority), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 0 {
		t.Fatalf("expired-at-mutation guard rows=%#v err=%v", rows.Rows, err)
	}
	server.store.now = originalClock
	rows, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: authorityArgs(authority), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("pre-revocation guard rows=%#v err=%v", rows.Rows, err)
	}
	if err := server.store.DeleteAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), token.AccessToken)); err != nil {
		t.Fatal(err)
	}
	rows, err = db.Query(context.Background(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: authorityArgs(authority), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 0 {
		t.Fatalf("revoked guard rows=%#v err=%v", rows.Rows, err)
	}
}

func authorityArgs(authority func() (string, []any)) []any {
	_, args := authority()
	return args
}

func TestAuthorizeUserResourcePolicyGuardUsesCurrentDatabaseState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy ClientGroupPolicy
	}{
		{"absent", ClientGroupPolicy{Managed: true}},
		{"unrestricted", ClientGroupPolicy{Managed: true, Revision: 1}},
		{"group", ClientGroupPolicy{Managed: true, Revision: 1, Prefix: "team"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := resourceAuthorizationServer(t, db, randomSecret(t))
			token := issueResourceToken(t, server, "goauthy.connections.read")
			server.oidc = &OIDCConfig{
				ClientGroupPolicy: func(context.Context, string) (ClientGroupPolicy, error) { return tc.policy, nil },
				ResolvePrincipal: func(context.Context, string) (PrincipalClaims, error) {
					return PrincipalClaims{Revision: 1, Groups: []string{"team-readers"}}, nil
				},
			}
			if tc.policy.Revision > 0 {
				var prefix any
				if tc.policy.Prefix != "" {
					prefix = tc.policy.Prefix
				}
				_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "resource-policy-seed", Statements: []rhiza.SQLStatement{
					{SQL: `INSERT INTO bootstrap_client_login_restrictions (client_id,restrict_group_prefix,revision,updated_at_unix_ms) VALUES (?,?,1,0)`, Args: []any{testClientID, prefix}},
					{SQL: `INSERT INTO rbac_groups (id,name,created_at_unix_ms,updated_at_unix_ms) VALUES ('resource-group','team-readers',0,0)`},
					{SQL: `INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) VALUES ('resource-user','resource-group',0)`},
				}})
				if err != nil {
					t.Fatal(err)
				}
			}
			r := httptest.NewRequest(http.MethodGet, "/resource", nil)
			r.Header.Set("Authorization", "Bearer "+token.AccessToken)
			_, authority, err := server.AuthorizeUserResource(r, "goauthy.connections.read", resourceAuthorizationAudience)
			if err != nil {
				t.Fatal(err)
			}
			assertGuard := func(want int) {
				t.Helper()
				guard, args := authority()
				rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
				if err != nil || len(rows.Rows) != want {
					t.Fatalf("guard rows=%v err=%v want=%d", rows.Rows, err, want)
				}
			}
			assertGuard(1)
			mutation := rhiza.ExecuteRequest{RequestID: "resource-policy-change"}
			switch tc.name {
			case "absent":
				mutation.SQL = `INSERT INTO bootstrap_client_login_restrictions (client_id,restrict_group_prefix,revision,updated_at_unix_ms) VALUES (?,NULL,1,0)`
				mutation.Args = []any{testClientID}
			case "unrestricted":
				mutation.SQL = `UPDATE bootstrap_client_login_restrictions SET revision=2`
			case "group":
				mutation.SQL = `DELETE FROM rbac_user_groups WHERE subject='resource-user'`
			}
			if _, err := storage.Execute(t.Context(), db, mutation); err != nil {
				t.Fatal(err)
			}
			assertGuard(0)
		})
	}
}

func TestAuthorizeUserResourceRejectsMalformedWrongScopeAndMachineTokens(t *testing.T) {
	db := oauthTestDB(t)
	server := resourceAuthorizationServer(t, db, randomSecret(t))
	wrong := issueResourceToken(t, server, "goauthy.read")
	wrongAudience := issueResourceTokenForAudience(t, server, "goauthy.connections.read", wrongResourceAuthorizationAudience)
	missingAudience := issueResourceTokenForAudience(t, server, "goauthy.connections.read", "")
	for _, tc := range []struct {
		name, authorization string
	}{
		{"malformed", "Bearer"},
		{"wrong scope", "Bearer " + wrong.AccessToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/resource", nil)
			r.Header.Set("Authorization", tc.authorization)
			if _, _, err := server.AuthorizeUserResource(r, "goauthy.connections.read", resourceAuthorizationAudience); err == nil {
				t.Fatal("accepted invalid resource authorization")
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "Bearer "+wrong.AccessToken)
	r.Header.Add("Authorization", "Bearer "+wrong.AccessToken)
	if _, _, err := server.AuthorizeUserResource(r, "goauthy.connections.read", resourceAuthorizationAudience); err == nil {
		t.Fatal("accepted duplicate authorization headers")
	}
	for name, accessToken := range map[string]string{"wrong audience": wrongAudience.AccessToken, "missing audience": missingAudience.AccessToken} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/resource", nil)
			r.Header.Set("Authorization", "Bearer "+accessToken)
			if _, _, err := server.AuthorizeUserResource(r, "goauthy.connections.read", resourceAuthorizationAudience); err == nil {
				t.Fatal("accepted token without the required resource audience")
			}
		})
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "resource-disable-owner", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"resource-user"}}); err != nil {
		t.Fatal(err)
	}
	// The wrong-scope token is already rejected; issue a correctly scoped token
	// to prove the live owner check, then disable that owner.
	server2 := resourceAuthorizationServer(t, oauthTestDB(t), randomSecret(t))
	valid := issueResourceToken(t, server2, "goauthy.connections.read")
	db2 := server2.store.db
	if _, err := storage.Execute(context.Background(), db2, rhiza.ExecuteRequest{RequestID: "resource-disable-owner-live", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"resource-user"}}); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "Bearer "+valid.AccessToken)
	if _, _, err := server2.AuthorizeUserResource(r, "goauthy.connections.read", resourceAuthorizationAudience); err == nil {
		t.Fatal("accepted disabled resource owner")
	}
	server.store.client.(*fosite.DefaultClient).Scopes = append(server.store.client.(*fosite.DefaultClient).Scopes, "goauthy.connections.read")
	machine := decodeToken(t, postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.connections.read"}}))
	r = httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "Bearer "+machine.AccessToken)
	if _, _, err := server.AuthorizeUserResource(r, "goauthy.connections.read", resourceAuthorizationAudience); err == nil {
		t.Fatal("accepted client credentials as user resource owner")
	}
}

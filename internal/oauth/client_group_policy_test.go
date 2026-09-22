package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestClientGroupPolicyFinalAuthorizationAndRaces(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		groups  []string
		mutate  string
		allowed bool
	}{
		{name: "upstream raw prefix permits punctuation suffix", groups: []string{"team-admin"}, allowed: true},
		{name: "case sensitive deny", groups: []string{"Team/a"}},
		{name: "membership revision race", groups: []string{"team/a"}, mutate: "principal"},
		{name: "policy revision race", groups: []string{"team/a"}, mutate: "policy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := PrincipalClaims{Roles: []string{"viewer"}, Groups: test.groups, Revision: 1}
			server := clientGroupPolicyServer(t, &state)
			if test.mutate != "" {
				server.beforeAuthorizationIssue = func() {
					server.beforeAuthorizationIssue = nil
					var sql string
					if test.mutate == "principal" {
						sql = `UPDATE rbac_principal_versions SET revision=2 WHERE subject='user-1'`
					} else {
						sql = `UPDATE bootstrap_client_login_restrictions SET revision=2 WHERE client_id='browser-client'`
					}
					if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "group-policy-race-" + test.mutate, SQL: sql}); err != nil {
						t.Fatal(err)
					}
				}
			}
			response := policyAuthorize(t, server, byte(len(test.name)))
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil {
				t.Fatalf("location=%q err=%v", response.Header().Get("Location"), err)
			}
			if test.allowed {
				if response.Code < http.StatusMultipleChoices || response.Code >= http.StatusBadRequest || location.Query().Get("code") == "" {
					t.Fatalf("allowed status=%d location=%q", response.Code, response.Header().Get("Location"))
				}
				return
			}
			if location.Query().Get("code") != "" {
				t.Fatalf("denied issuance returned code: %q", response.Header().Get("Location"))
			}
			assertNoAuthorizationState(t, server.store.db)
		})
	}
}

func TestClientGroupPolicyForwardAuthUsesCurrentGroups(t *testing.T) {
	t.Parallel()
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	server := clientGroupPolicyServer(t, &state)
	codeResponse := policyAuthorize(t, server, 9)
	location, err := url.Parse(codeResponse.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization location=%q err=%v", codeResponse.Header().Get("Location"), err)
	}
	verifier := strings.Repeat("p", 43)
	token := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	if response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token.AccessToken, nil)); response.Code != http.StatusOK {
		t.Fatalf("matching groups status=%d", response.Code)
	}
	state.Groups, state.Revision = []string{"other"}, 2
	assertForwardAuthUnauthorized(t, server, forwardAuthRequest(http.MethodGet, token.AccessToken, nil))
}

func TestClientGroupPolicyCodeAndRefreshUseCurrentGroups(t *testing.T) {
	t.Parallel()
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	server := clientGroupPolicyServer(t, &state)
	codeResponse := policyAuthorize(t, server, 10)
	location, err := url.Parse(codeResponse.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization location=%q err=%v", codeResponse.Header().Get("Location"), err)
	}
	state.Groups, state.Revision = []string{"other"}, 2
	if response := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("p", 43)}}); response.Code == http.StatusOK {
		t.Fatal("unmatched current groups redeemed authorization code")
	}
	state.Groups, state.Revision = []string{"team/a"}, 1
	codeResponse = policyAuthorize(t, server, 11)
	location, err = url.Parse(codeResponse.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("second authorization location=%q err=%v", codeResponse.Header().Get("Location"), err)
	}
	issued := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("p", 43)}}))
	state.Groups, state.Revision = []string{"other"}, 2
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "client-policy-refresh-current", SQL: `UPDATE rbac_principal_versions SET revision=2 WHERE subject='user-1'`}); err != nil {
		t.Fatal(err)
	}
	if response := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}); response.Code == http.StatusOK {
		t.Fatal("unmatched current groups refreshed token")
	}
}

func TestClientGroupPolicyDoesNotEmitGroupsWithoutScope(t *testing.T) {
	t.Parallel()
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	server := clientGroupPolicyServer(t, &state)
	response := policyAuthorize(t, server, 12)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization location=%q err=%v", response.Header().Get("Location"), err)
	}
	issued := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("p", 43)}}))
	assertRBACJWTClaims(t, issued.IDToken, []string{"viewer"}, nil, false)
}

func TestClearedClientGroupPolicyIsRevisionBoundUnrestricted(t *testing.T) {
	t.Parallel()
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"other"}, Revision: 1}
	server := clientGroupPolicyServer(t, &state)
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "client-policy-clear", SQL: `UPDATE bootstrap_client_login_restrictions SET restrict_group_prefix=NULL,revision=2 WHERE client_id='browser-client'`}); err != nil {
		t.Fatal(err)
	}
	server.oidc.ClientGroupPolicy = func(context.Context, string) (ClientGroupPolicy, error) {
		return ClientGroupPolicy{Managed: true, Revision: 2}, nil
	}
	response := policyAuthorize(t, server, 13)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("cleared policy authorization location=%q err=%v", response.Header().Get("Location"), err)
	}
	issued := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("p", 43)}}))
	refreshedResponse := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}})
	if refreshedResponse.Code != http.StatusOK {
		t.Fatalf("cleared policy refresh status=%d", refreshedResponse.Code)
	}
	refreshed := decodeOIDCToken(t, refreshedResponse)
	if response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, refreshed.AccessToken, nil)); response.Code != http.StatusOK {
		t.Fatalf("cleared policy forward auth status=%d", response.Code)
	}
	server.beforeAuthorizationIssue = func() {
		server.beforeAuthorizationIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "client-policy-clear-race", SQL: `UPDATE bootstrap_client_login_restrictions SET revision=3 WHERE client_id='browser-client'`}); err != nil {
			t.Fatal(err)
		}
	}
	beforeCodes, beforePKCE := authorizationStateCount(t, server.store.db)
	raced := policyAuthorize(t, server, 14)
	if location, err := url.Parse(raced.Header().Get("Location")); err != nil || location.Query().Get("code") != "" {
		t.Fatalf("cleared policy race status=%d location=%q err=%v", raced.Code, raced.Header().Get("Location"), err)
	}
	afterCodes, afterPKCE := authorizationStateCount(t, server.store.db)
	if afterCodes != beforeCodes || afterPKCE != beforePKCE {
		t.Fatalf("cleared policy race wrote state before=(%d,%d) after=(%d,%d)", beforeCodes, beforePKCE, afterCodes, afterPKCE)
	}
}

func clientGroupPolicyServer(t *testing.T, state *PrincipalClaims) *Server {
	t.Helper()
	db := oauthTestDB(t)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "client-group-policy-schema", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO bootstrap_client_login_restrictions (client_id,restrict_group_prefix,revision,updated_at_unix_ms) VALUES ('browser-client','team',1,0)`},
		{SQL: `INSERT INTO identity_users (subject,username,password_phc) VALUES ('user-1','user-1','phc')`},
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES ('user-1',1,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	return clientGroupPolicyOIDCServer(t, db, state)
}

func clientGroupPolicyOIDCServer(t *testing.T, db *rhiza.DB, state *PrincipalClaims) *Server {
	t.Helper()
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ValidateSubject:  func(context.Context, string) error { return nil },
		ResolvePrincipal: func(context.Context, string) (PrincipalClaims, error) { return *state, nil },
		ClientGroupPolicy: func(context.Context, string) (ClientGroupPolicy, error) {
			return ClientGroupPolicy{Managed: true, Prefix: "team", Revision: 1}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func policyAuthorize(t *testing.T, server *Server, seed byte) *httptest.ResponseRecorder {
	t.Helper()
	verifier := strings.Repeat("p", 43)
	values := oidcAuthorizationValues(verifier, "policy")
	sid := oidcTestSessionID(seed)
	insertPolicyBrowserSession(t, server, sid)
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", strings.Fields(values.Get("scope")), time.Unix(1_700_000_000, 0).UTC(), sid, oidcAuthMethodPwd)
	return response
}

func insertPolicyBrowserSession(t *testing.T, server *Server, sid string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "client-policy-session-" + sid[:16], SQL: `INSERT INTO browser_sessions (token_digest,subject,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES (?,?,0,4102444800000,4102444800000)`, Args: []any{sid, "user-1"}}); err != nil {
		t.Fatal(err)
	}
}

func authorizationStateCount(t *testing.T, db *rhiza.DB) (int64, int64) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_authorize_codes), (SELECT COUNT(*) FROM oauth_pkce_requests)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("authorization state=%#v err=%v", result.Rows, err)
	}
	codes, codesOK := result.Rows[0][0].(int64)
	pkce, pkceOK := result.Rows[0][1].(int64)
	if !codesOK || !pkceOK {
		t.Fatalf("authorization state types=%#v", result.Rows)
	}
	return codes, pkce
}

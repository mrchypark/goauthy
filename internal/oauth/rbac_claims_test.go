package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func TestOIDCPrincipalClaimsAreCurrentAndScoped(t *testing.T) {
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	resolves := 0
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
		resolves++
		return state, nil
	})
	verifier := strings.Repeat("r", 43)
	issued := decodeOIDCToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, "openid groups goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	if resolves != 1 {
		t.Fatalf("authorization-code resolver calls=%d, want 1", resolves)
	}
	assertRBACJWTClaims(t, issued.IDToken, []string{"viewer"}, []string{"team/a"}, true)
	assertRBACIntrospection(t, server, issued.AccessToken, []string{"viewer"}, []string{"team/a"}, true)

	state = PrincipalClaims{Roles: []string{"admin"}, Groups: []string{"team/b"}, Revision: 1}
	refreshed := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}))
	if resolves != 3 {
		t.Fatalf("refresh resolver calls=%d, want 3", resolves)
	}
	assertRBACJWTClaims(t, refreshed.IDToken, []string{"admin"}, []string{"team/b"}, true)
	assertRBACIntrospection(t, server, refreshed.AccessToken, []string{"admin"}, []string{"team/b"}, true)
}

func TestOIDCPrincipalClaimsRejectResolverFailureBeforeRefreshCommit(t *testing.T) {
	blocked := false
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
		if blocked {
			return PrincipalClaims{}, errors.New("revoked")
		}
		return PrincipalClaims{Roles: []string{"viewer"}, Revision: 1}, nil
	})
	verifier := strings.Repeat("s", 43)
	issued := decodeOIDCToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, "openid goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	blocked = true
	if response := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}); response.Code == http.StatusOK {
		t.Fatal("revoked principal refreshed tokens")
	}
	blocked = false
	if response := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}); response.Code != http.StatusOK {
		t.Fatalf("resolver failure consumed refresh token: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUserInfoUsesCurrentPrincipalClaimsAndGroupsScope(t *testing.T) {
	state := PrincipalClaims{Roles: []string{"viewer"}, Groups: []string{"team/a"}, Revision: 1}
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) { return state, nil })
	withGroups := issueRBACAccessToken(t, server, strings.Repeat("t", 43), "openid groups goauthy.read offline_access")
	withoutGroups := issueRBACAccessToken(t, server, strings.Repeat("u", 43), "openid goauthy.read offline_access")
	state = PrincipalClaims{Roles: []string{"admin"}, Groups: []string{"team/b"}, Revision: 1}
	for _, test := range []struct {
		token  string
		groups bool
	}{{withGroups, true}, {withoutGroups, false}} {
		response := httptest.NewRecorder()
		server.UserInfoHandler().ServeHTTP(response, userInfoRequest(http.MethodGet, test.token, nil))
		var got map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || response.Code != http.StatusOK {
			t.Fatalf("userinfo status=%d body=%s err=%v", response.Code, response.Body.String(), err)
		}
		if !sameStringClaims(got["roles"], []string{"admin"}) || (test.groups != (got["groups"] != nil)) || test.groups && !sameStringClaims(got["groups"], []string{"team/b"}) {
			t.Fatalf("userinfo groups=%t claims=%#v", test.groups, got)
		}
	}
}

func TestOIDCPrincipalClaimsRejectMalformedResolverResult(t *testing.T) {
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
		return PrincipalClaims{Roles: []string{"viewer", "viewer"}, Revision: 1}, nil
	})
	verifier := strings.Repeat("v", 43)
	if response := postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, "openid goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}); response.Code == http.StatusOK {
		t.Fatal("malformed resolver result issued tokens")
	}
}

func TestOIDCPrincipalClaimsRejectMissingRevision(t *testing.T) {
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
		return PrincipalClaims{Roles: []string{"viewer"}}, nil
	})
	verifier := strings.Repeat("w", 43)
	if response := postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, "openid goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}); response.Code == http.StatusOK {
		t.Fatal("missing principal revision issued tokens")
	}
}

func TestOIDCPrincipalRevisionGuardRejectsCodeAndRefreshWithoutArtifacts(t *testing.T) {
	for _, test := range []struct {
		name                                      string
		form                                      func(t *testing.T, server *Server, verifier string) url.Values
		failedAccess, failedRefresh, failedActive int64
		issuedAccess, issuedRefresh, issuedActive int64
	}{
		{name: "code", form: func(t *testing.T, server *Server, verifier string) url.Values {
			t.Helper()
			code := issueRBACCode(t, server, verifier, "openid goauthy.read offline_access")
			return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}
		}, issuedAccess: 1, issuedRefresh: 1, issuedActive: 1},
		{name: "refresh", form: func(t *testing.T, server *Server, verifier string) url.Values {
			t.Helper()
			issued := decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, "openid goauthy.read offline_access")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
			return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}
		}, failedAccess: 1, failedRefresh: 1, failedActive: 1, issuedAccess: 1, issuedRefresh: 2, issuedActive: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := PrincipalClaims{Roles: []string{"viewer"}, Revision: 1}
			server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
				return state, nil
			})
			form := test.form(t, server, strings.Repeat(test.name[:1], 43))
			server.beforeTokenIssue = revisionBumpHook(t, server, test.name)
			response := postToken(server, form)
			if response.Code == http.StatusOK {
				t.Fatalf("stale revision %s exchange issued tokens", test.name)
			}
			assertRBACTokenRows(t, server, test.failedAccess, test.failedRefresh, test.failedActive)
			state.Revision = 2
			if response := postToken(server, form); response.Code != http.StatusOK {
				t.Fatalf("current revision %s retry status=%d body=%s", test.name, response.Code, response.Body.String())
			}
			assertRBACTokenRows(t, server, test.issuedAccess, test.issuedRefresh, test.issuedActive)
		})
	}
}

func assertRBACTokenRows(t *testing.T, server *Server, access, refresh, active int64) {
	t.Helper()
	result, err := server.store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT
		(SELECT COUNT(*) FROM oauth_access_tokens),
		(SELECT COUNT(*) FROM oauth_refresh_tokens),
		(SELECT COUNT(*) FROM oauth_refresh_tokens WHERE active=1)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 3 || result.Rows[0][0] != access || result.Rows[0][1] != refresh || result.Rows[0][2] != active {
		t.Fatalf("token artifacts=%#v err=%v", result.Rows, err)
	}
}

func revisionBumpHook(t *testing.T, server *Server, name string) func() {
	t.Helper()
	return func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "rbac-revision-bump-" + name, SQL: `UPDATE rbac_principal_versions SET revision=2 WHERE subject='user-1'`}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrincipalGroupPolicyRejectsWhitespaceAndBackslash(t *testing.T) {
	for _, group := range []string{"team/a", "team-a"} {
		if _, err := canonicalPrincipalClaims(PrincipalClaims{Roles: []string{}, Groups: []string{group}, Revision: 1}); err != nil {
			t.Fatalf("valid group %q: %v", group, err)
		}
	}
	for _, group := range []string{"team a", `team\\a`} {
		if _, err := canonicalPrincipalClaims(PrincipalClaims{Roles: []string{}, Groups: []string{group}, Revision: 1}); err == nil {
			t.Fatalf("invalid group %q accepted", group)
		}
	}
}

func TestClientCredentialsRejectGroupsScope(t *testing.T) {
	server := rbacClaimsServer(t, func(context.Context, string) (PrincipalClaims, error) {
		return PrincipalClaims{Roles: []string{"admin"}, Revision: 1}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {groupsScope}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_scope"`) {
		t.Fatalf("client credentials groups status=%d body=%s", response.Code, response.Body.String())
	}
}

func rbacClaimsServer(t *testing.T, resolver func(context.Context, string) (PrincipalClaims, error)) *Server {
	t.Helper()
	db := oauthTestDB(t)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "rbac-claims-user", Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO identity_users (subject,username,password_phc) VALUES ('user-1','user-1','phc')`}, {SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES ('user-1',1,0)`}}}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil }, ResolvePrincipal: resolver,
		ValidateSubject: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func issueRBACCode(t *testing.T, server *Server, verifier, scopes string) string {
	t.Helper()
	sid := oidcTestSessionID(0)
	ensureOIDCTestBrowserSession(t, server, sid)
	values := oidcAuthorizationValues(verifier, "nonce")
	values.Set("scope", scopes)
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", strings.Fields(scopes), time.Unix(1_700_000_000, 0).UTC(), sid, oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return location.Query().Get("code")
}

func issueRBACAccessToken(t *testing.T, server *Server, verifier, scopes string) string {
	t.Helper()
	return decodeOIDCToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, scopes)}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})).AccessToken
}

func assertRBACJWTClaims(t *testing.T, token string, roles, groups []string, hasGroups bool) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT=%q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil || !sameStringClaims(got["roles"], roles) || (hasGroups != (got["groups"] != nil)) || hasGroups && !sameStringClaims(got["groups"], groups) {
		t.Fatalf("JWT claims=%#v err=%v", got, err)
	}
}

func assertRBACIntrospection(t *testing.T, server *Server, token string, roles, groups []string, hasGroups bool) {
	t.Helper()
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || response.Code != http.StatusOK || !sameStringClaims(got["roles"], roles) || (hasGroups != (got["groups"] != nil)) || hasGroups && !sameStringClaims(got["groups"], groups) {
		t.Fatalf("introspection status=%d claims=%#v err=%v", response.Code, got, err)
	}
}

func sameStringClaims(value any, want []string) bool {
	got, ok := value.([]any)
	if !ok || len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

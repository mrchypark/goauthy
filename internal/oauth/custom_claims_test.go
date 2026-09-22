package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCustomClaimsAreScopedAndSurfaceSpecific(t *testing.T) {
	t.Parallel()
	accessValue := json.RawMessage(`"access-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	without := decodeOIDCToken(t, postToken(server, codeTokenForm(t, server, "a", "openid goauthy.read offline_access")))
	if got := jwtPayload(t, without.IDToken); got["custom"] != nil {
		t.Fatalf("unrequested custom scope leaked into ID token: %#v", got)
	}
	with := decodeOIDCToken(t, postToken(server, codeTokenForm(t, server, "b", "openid employee goauthy.read offline_access")))
	id := jwtPayload(t, with.IDToken)
	if custom, _ := id["custom"].(map[string]any); custom["id_value"] != "id-v1" || custom["access_value"] != nil {
		t.Fatalf("ID custom claims=%#v", id)
	}
	access := jwtPayload(t, with.AccessToken)
	if access["iss"] != oidcTestIssuer || access["sub"] != "user-1" || access["azp"] != testClientID || access["typ"] != "Bearer" || access["scope"] != "openid employee goauthy.read offline_access" || access["custom"].(map[string]any)["access_value"] != "access-v1" {
		t.Fatalf("signed access claims=%#v", access)
	}
	assertCustomAccessSurface(t, server.UserInfoHandler(), with.AccessToken, "access-v1")
	assertCustomIntrospection(t, server, with.AccessToken, "access-v1")

	accessValue = json.RawMessage(`"access-v2"`)
	assertCustomAccessSurface(t, server.UserInfoHandler(), with.AccessToken, "access-v2")
	assertCustomIntrospection(t, server, with.AccessToken, "access-v2")
}

func TestCustomClaimRootCollisionFailsBeforeArtifacts(t *testing.T) {
	t.Parallel()
	accessValue := json.RawMessage(`"access-v1"`)
	server := customClaimsServer(t, true, &accessValue)
	sid := oidcTestSessionID(3)
	ensureOIDCTestBrowserSession(t, server, sid)
	values := oidcAuthorizationValues(strings.Repeat("c", 43), "nonce")
	values.Set("scope", "openid employee goauthy.read offline_access")
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", strings.Fields(values.Get("scope")), oidcTestAuthTime, sid, oidcAuthMethodPwd)
	if location, _ := url.Parse(response.Header().Get("Location")); location != nil && location.Query().Get("code") != "" {
		t.Fatal("root collision issued an authorization code")
	}
	assertRBACTokenRows(t, server, 0, 0, 0)
}

func TestCustomClaimsCanMixNestedAndRootScopes(t *testing.T) {
	t.Parallel()
	accessValue := json.RawMessage(`"unused"`)
	server := customClaimsServer(t, false, &accessValue)
	server.oidc.ResolveCustomClaims = func(ctx context.Context, _ string, granted []string) (claims.Resolved, error) {
		catalog, err := claims.NewStore(server.store.db).CatalogRevision(ctx)
		if err != nil {
			return claims.Resolved{}, err
		}
		for _, scope := range granted {
			if scope == "employee" {
				return claims.Resolved{
					ID: map[string]json.RawMessage{"nested_id": json.RawMessage(`"nested-id"`)}, IDRoot: map[string]json.RawMessage{"root_id": json.RawMessage(`"root-id"`)},
					Access: map[string]json.RawMessage{"nested_access": json.RawMessage(`"nested-access"`)}, AccessRoot: map[string]json.RawMessage{"root_access": json.RawMessage(`"root-access"`)}, CatalogRevision: catalog,
				}, nil
			}
		}
		return claims.Resolved{CatalogRevision: catalog}, nil
	}
	issued := decodeOIDCToken(t, postToken(server, codeTokenForm(t, server, "m", "openid employee goauthy.read offline_access")))
	id := jwtPayload(t, issued.IDToken)
	if id["root_id"] != "root-id" || id["custom"].(map[string]any)["nested_id"] != "nested-id" {
		t.Fatalf("mixed ID claims=%#v", id)
	}
	assertMixedAccessSurface(t, server.UserInfoHandler(), issued.AccessToken)
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {issued.AccessToken}}, testClientID, testClientSecret)
	got := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || response.Code != http.StatusOK || got["root_access"] != "root-access" || got["custom"].(map[string]any)["nested_access"] != "nested-access" || got["goauthy_custom_root"] != nil {
		t.Fatalf("mixed introspection status=%d claims=%#v err=%v", response.Code, got, err)
	}
}

func TestCustomUserScopesAreRejectedOutsideAuthorizationCodeAndRefresh(t *testing.T) {
	t.Parallel()
	accessValue := json.RawMessage(`"access-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	for name, form := range map[string]url.Values{
		"client credentials": {"grant_type": {"client_credentials"}, "scope": {"employee"}},
	} {
		t.Run(name, func(t *testing.T) {
			if response := postToken(server, form); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_scope"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	verifier := strings.Repeat("x", 43)
	source := decodeToken(t, postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {issueExchangeCodeFor(t, server, "user-1", "goauthy.read")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	if response := postToken(server, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source.AccessToken}, "subject_token_type": {accessTokenType}, "scope": {"employee"}}); response.Code == http.StatusOK {
		t.Fatal("token exchange widened a source that did not grant employee")
	}
	if response := postToken(server, url.Values{"grant_type": {"client_credentials"}, "scope": {"profile"}}); response.Code != http.StatusOK {
		t.Fatalf("built-in scope rejected: status=%d body=%s", response.Code, response.Body.String())
	}
	if err := server.AuthorizeDeviceClient(context.Background(), testClientID, []string{"employee"}); err == nil {
		t.Fatal("custom scope accepted for device authorization")
	}
}

func TestCustomClaimCatalogAndPrincipalRacesLeaveNoArtifacts(t *testing.T) {
	t.Parallel()
	for name, mutation := range map[string]string{
		"catalog":   `UPDATE claims_catalog SET revision=revision+1 WHERE id=1`,
		"principal": `UPDATE rbac_principal_versions SET revision=revision+1 WHERE subject='user-1'`,
	} {
		t.Run(name, func(t *testing.T) {
			accessValue := json.RawMessage(`"access-v1"`)
			server := customClaimsServer(t, false, &accessValue)
			form := codeTokenForm(t, server, name[:1], "openid employee goauthy.read offline_access")
			server.beforeTokenIssue = func() {
				server.beforeTokenIssue = nil
				if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "custom-claim-race-" + name, SQL: mutation}); err != nil {
					t.Fatal(err)
				}
			}
			if response := postToken(server, form); response.Code == http.StatusOK {
				t.Fatalf("stale %s issued tokens", name)
			}
			assertRBACTokenRows(t, server, 0, 0, 0)
		})
	}
}

func TestCustomClaimRefreshCatalogAndPrincipalRacesLeaveNoArtifacts(t *testing.T) {
	t.Parallel()
	for name, mutation := range map[string]string{
		"catalog":   `UPDATE claims_catalog SET revision=revision+1 WHERE id=1`,
		"principal": `UPDATE rbac_principal_versions SET revision=revision+1 WHERE subject='user-1'`,
	} {
		t.Run(name, func(t *testing.T) {
			accessValue := json.RawMessage(`"access-v1"`)
			server := customClaimsServer(t, false, &accessValue)
			issued := decodeOIDCToken(t, postToken(server, codeTokenForm(t, server, name[:1], "openid employee goauthy.read offline_access")))
			server.beforeTokenIssue = func() {
				server.beforeTokenIssue = nil
				if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "custom-claim-refresh-race-" + name, SQL: mutation}); err != nil {
					t.Fatal(err)
				}
			}
			if response := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}); response.Code == http.StatusOK {
				t.Fatalf("stale %s refresh issued tokens", name)
			}
			assertRBACTokenRows(t, server, 1, 1, 1)
		})
	}
}

func customClaimsServer(t *testing.T, rootCollision bool, accessValue *json.RawMessage) *Server {
	t.Helper()
	db := oauthTestDB(t)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "custom-claims-user", Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO identity_users (subject,username,password_phc) VALUES ('user-1','user-1','phc')`}, {SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES ('user-1',1,0)`}}}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithOIDC(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{exchangeResource}, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		ValidateSubject:  func(context.Context, string) error { return nil },
		ResolvePrincipal: func(context.Context, string) (PrincipalClaims, error) { return PrincipalClaims{Revision: 1}, nil },
		BootstrapClientScopes: func(context.Context, string) (claims.ClientScopes, error) {
			return claims.ClientScopes{ClientID: testClientID, Allowed: []string{"employee", "profile"}, Revision: 1}, nil
		},
		ResolveCustomClaims: func(ctx context.Context, _ string, granted []string) (claims.Resolved, error) {
			catalog, catalogErr := claims.NewStore(db).CatalogRevision(ctx)
			if catalogErr != nil {
				return claims.Resolved{}, catalogErr
			}
			for _, scope := range granted {
				if scope == "employee" {
					id := map[string]json.RawMessage{"id_value": json.RawMessage(`"id-v1"`)}
					idRoot := map[string]json.RawMessage(nil)
					if rootCollision {
						id = nil
						idRoot = map[string]json.RawMessage{"sub": json.RawMessage(`"collision"`)}
					}
					return claims.Resolved{ID: id, IDRoot: idRoot, Access: map[string]json.RawMessage{"access_value": *accessValue}, CatalogRevision: catalog}, nil
				}
			}
			return claims.Resolved{ID: map[string]json.RawMessage{}, Access: map[string]json.RawMessage{}, CatalogRevision: catalog}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func codeTokenForm(t *testing.T, server *Server, seed, scopes string) url.Values {
	t.Helper()
	verifier := strings.Repeat(seed, 43)
	return url.Values{"grant_type": {"authorization_code"}, "code": {issueRBACCode(t, server, verifier, scopes)}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}
}

func jwtPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func assertCustomAccessSurface(t *testing.T, handler http.Handler, token, want string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, userInfoRequest(http.MethodGet, token, nil))
	got := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || response.Code != http.StatusOK || got["custom"].(map[string]any)["access_value"] != want {
		t.Fatalf("status=%d claims=%#v err=%v", response.Code, got, err)
	}
}

func assertMixedAccessSurface(t *testing.T, handler http.Handler, token string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, userInfoRequest(http.MethodGet, token, nil))
	got := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || response.Code != http.StatusOK || got["root_access"] != "root-access" || got["custom"].(map[string]any)["nested_access"] != "nested-access" {
		t.Fatalf("status=%d claims=%#v err=%v", response.Code, got, err)
	}
}

func assertCustomIntrospection(t *testing.T, server *Server, token, want string) {
	t.Helper()
	response := postOAuthForm(server.IntrospectionHandler(), url.Values{"token": {token}}, testClientID, testClientSecret)
	got := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || response.Code != http.StatusOK || got["custom"].(map[string]any)["access_value"] != want {
		t.Fatalf("status=%d claims=%#v err=%v", response.Code, got, err)
	}
}

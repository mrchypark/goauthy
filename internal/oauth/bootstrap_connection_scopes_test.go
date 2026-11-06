package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestBootstrapConnectionScopesRequireCatalogPolicyPKCE(t *testing.T) {
	ctx := t.Context()
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	seedOAuthUser(t, db, "scope-admin")
	// Seed only synthetic fixture authority. Catalog and client-policy changes
	// below still pass through the real administrator-authorized Store methods.
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "bootstrap-scope-fixture-authority", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_principal_versions(subject,revision,updated_at_unix_ms) VALUES('user-1',1,0)`},
		{SQL: `INSERT OR IGNORE INTO rbac_roles(id,name,created_at_unix_ms,updated_at_unix_ms) VALUES('scope-admin-role','goauthy_admin',0,0)`},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) SELECT 'scope-admin',id,0 FROM rbac_roles WHERE name='goauthy_admin'`},
	}}); err != nil {
		t.Fatal(err)
	}
	cs := claims.NewStore(db)
	const connections = "https://app.example/connections"
	resources := []string{"https://app.example/grant", "https://app.example/compos", connections, "https://app.example/providers"}
	s, err := NewServerWithOIDC(ctx, db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, resources, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
		DefaultAudiences: map[string]string{testClientID: resources[0]}, BootstrapClientScopes: cs.BootstrapClientScopes, CustomScopeExists: cs.ScopeExists, ResolveCustomClaims: cs.Resolve,
		ValidateSubject: func(context.Context, string) error { return nil }, ResolvePrincipal: func(context.Context, string) (PrincipalClaims, error) { return PrincipalClaims{Revision: 1}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	policies := clients.NewStore(db, nil)
	if err := policies.EnsureBootstrap(ctx, testClientID); err != nil {
		t.Fatal(err)
	}
	if err := s.PinBootstrapConnections(ctx, connections); err != nil {
		t.Fatal(err)
	}
	names := []string{"goauthy.connections.read", "goauthy.connections.use", "goauthy.connections.write"}
	authorize := func(scope string, n int) (string, string) {
		verifier := strings.Repeat("k", 43)
		sid := oidcTestSessionID(byte(n))
		ensureOIDCTestBrowserSession(t, s, sid)
		values := oidcAuthorizationValues(verifier, "bootstrap-scope-nonce")
		values.Set("scope", "openid goauthy.read "+scope)
		values.Set("resource", connections)
		w := httptest.NewRecorder()
		s.CompleteAuthorizationWithSession(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", strings.Fields(values.Get("scope")), oidcTestAuthTime, sid, oidcAuthMethodPwd)
		u, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("code"), u.Query().Get("error")
	}
	for i, name := range names {
		if code, reason := authorize(name, 20+i); code != "" || reason != "invalid_scope" {
			t.Fatalf("unconfigured scope accepted or unexpected denial: scope=%s error=%s", name, reason)
		}
	}
	allowed := append([]string{"openid"}, names...)
	if _, err := cs.UpdateBootstrapClientScopes(ctx, "scope-admin", testClientID, 0, allowed, []string{"openid"}); !errors.Is(err, claims.ErrNotFound) {
		t.Fatalf("missing catalog scope accepted: %v", err)
	}
	for _, name := range names {
		rev, err := cs.CatalogRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cs.CreateScope(ctx, "user-1", rev, claims.Scope{Name: name}); !errors.Is(err, claims.ErrUnauthorized) {
			t.Fatalf("nonadmin scope creation: %v", err)
		}
		if _, err := cs.CreateScope(ctx, "scope-admin", rev, claims.Scope{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	updated, err := cs.UpdateBootstrapClientScopes(ctx, "scope-admin", testClientID, 0, allowed, []string{"openid"})
	if err != nil || updated.Revision != 1 {
		t.Fatalf("authorized scope policy: %v", err)
	}
	for i, name := range names {
		code, reason := authorize(name, 30+i)
		if code == "" || reason != "" {
			t.Fatalf("configured scope denied: %s %s", name, reason)
		}
		token := exchangeToken(t, s, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("k", 43)}})
		if !strings.Contains(" "+token.Scope+" ", " "+name+" ") {
			t.Fatal("requested connection scope missing")
		}
		r := httptest.NewRequest(http.MethodGet, "/resource", nil)
		r.Header.Set("Authorization", "Bearer "+token.AccessToken)
		if name == "goauthy.connections.use" {
			if _, _, _, err := s.AuthorizeConnectionUse(r, connections); err != nil {
				t.Fatalf("PKCE use token: %v", err)
			}
		} else {
			if _, _, err := s.AuthorizeUserResource(r, name, connections); err != nil {
				t.Fatalf("PKCE resource token: %v", err)
			}
		}
	}
}

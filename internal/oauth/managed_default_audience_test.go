package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestManagedDefaultAudienceAcrossGrants(t *testing.T) {
	s, db := crossClientExchangeServer(t)
	const id = "managed-defaults"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master"), []byte(base64.RawURLEncoding.EncodeToString(randomSecret(t))), 0600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	s.store.managedClients = clients.NewStore(db, keyring)
	guard := func() (string, []any) { return "1", nil }
	_, err = s.store.managedClients.CreateWithGuard(t.Context(), clients.NewRequest{
		ID: id, Confidential: true, RedirectURIs: []string{testRedirectURI},
		Scopes: []string{"goauthy.read", "offline_access"}, DefaultScopes: []string{"goauthy.read"},
		GrantTypes: []string{"client_credentials", "authorization_code", "refresh_token"},
		Audiences:  []string{crossExchangeTarget}, DefaultAudiences: []string{crossExchangeDefaultA, crossExchangeTarget},
	}, guard)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.store.managedClients.ReadSecretWithGuard(t.Context(), id, guard)
	if err != nil {
		t.Fatal(err)
	}
	check := func(token string, scopes []string) {
		t.Helper()
		response := postOAuthForm(s.IntrospectionHandler(), url.Values{"token": {token}}, id, secret)
		var body map[string]json.RawMessage
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || string(body["active"]) != "true" {
			t.Fatal("managed token is not active")
		}
		var audience []string
		if json.Unmarshal(body["aud"], &audience) != nil {
			t.Fatal("invalid introspection audience")
		}
		slices.Sort(audience)
		if !sameAccessStrings(audience, []string{crossExchangeDefaultA, crossExchangeTarget}) {
			t.Fatalf("default audience lost or duplicated: %v", audience)
		}
		if _, present := body[accessDefaultAudiencesExtra]; present {
			t.Fatal("private default snapshot leaked through introspection")
		}
		request, err := s.store.GetAccessTokenSession(t.Context(), s.accessTokens.AccessTokenSignature(t.Context(), token), nil)
		if err != nil || !sameAccessStrings(request.GetGrantedScopes(), scopes) {
			t.Fatal("persisted scope changed")
		}
		if err := s.accessTokens.ValidateAccessToken(t.Context(), request, token); err != nil {
			t.Fatalf("signed token did not match persisted audience: %v", err)
		}
	}
	for _, resource := range []string{"", crossExchangeTarget} {
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}
		if resource != "" {
			form.Set("resource", resource)
		}
		token := decodeToken(t, postCrossExchange(s, id, secret, form))
		assertCrossExchangeClaims(t, token.AccessToken, id, []string{id, crossExchangeDefaultA, crossExchangeTarget})
		check(token.AccessToken, []string{"goauthy.read"})
	}
	denied := postCrossExchange(s, id, secret, url.Values{"grant_type": {"client_credentials"}, "resource": {crossExchangeDefaultA}, "scope": {"goauthy.read"}})
	if denied.Code == http.StatusOK {
		t.Fatal("default expanded the explicit resource allow-list")
	}
	seedOAuthUser(t, db, "defaults-user")
	verifier := strings.Repeat("m", 43)
	form := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {testRedirectURI}, "scope": {"goauthy.read offline_access"}, "resource": {crossExchangeTarget}, "state": {strings.Repeat("s", 32)}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	s.WriteAuthorization(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+form.Encode(), nil), "defaults-user", []string{"goauthy.read", "offline_access"})
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization failed: %d", w.Code)
	}
	token := decodeToken(t, postCrossExchange(s, id, secret, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	check(token.AccessToken, []string{"goauthy.read", "offline_access"})
	refreshed := decodeToken(t, postCrossExchange(s, id, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token.RefreshToken}}))
	check(refreshed.AccessToken, []string{"goauthy.read", "offline_access"})
	form.Del("resource")
	w = httptest.NewRecorder()
	s.WriteAuthorization(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+form.Encode(), nil), "defaults-user", []string{"goauthy.read", "offline_access"})
	location, err = url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatal("default-only authorization failed")
	}
	defaultOnly := decodeToken(t, postCrossExchange(s, id, secret, url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}))
	checkDefaultOnly := func(access string) {
		t.Helper()
		check(access, []string{"goauthy.read", "offline_access"})
		stored, err := s.store.GetAccessTokenSession(t.Context(), s.accessTokens.AccessTokenSignature(t.Context(), access), nil)
		if err != nil || len(stored.GetGrantedAudience()) != 0 {
			t.Fatal("default-only token gained explicit resource grants")
		}
	}
	checkDefaultOnly(defaultOnly.AccessToken)
	defaultRefresh := decodeToken(t, postCrossExchange(s, id, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {defaultOnly.RefreshToken}}))
	checkDefaultOnly(defaultRefresh.AccessToken)
	c, err := s.store.managedClients.GetWithGuard(t.Context(), id, guard)
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.store.managedClients.UpdateWithGuard(t.Context(), id, c.Revision, clients.UpdateRequest{
		Confidential: c.Confidential, Enabled: true, RedirectURIs: c.RedirectURIs,
		Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes,
		Audiences: c.Audiences, DefaultAudiences: []string{crossExchangeDefaultB},
	}, guard)
	if err != nil {
		t.Fatal(err)
	}
	for _, access := range []string{token.AccessToken, refreshed.AccessToken, defaultOnly.AccessToken, defaultRefresh.AccessToken} {
		response := postOAuthForm(s.IntrospectionHandler(), url.Values{"token": {access}}, id, secret)
		var body struct{ Active bool }
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Active {
			t.Fatal("old token survived default audience generation change")
		}
	}
	if postCrossExchange(s, id, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}).Code == http.StatusOK {
		t.Fatal("old refresh token survived default audience generation change")
	}
	revised := decodeToken(t, postCrossExchange(s, id, secret, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}))
	assertCrossExchangeClaims(t, revised.AccessToken, id, []string{id, crossExchangeDefaultB})
	beforeAccess, beforeRequests := crossExchangeArtifacts(t, s)
	s.beforeTokenIssue = func() {
		s.beforeTokenIssue = nil
		_, err := s.store.managedClients.UpdateWithGuard(t.Context(), id, c.Revision, clients.UpdateRequest{
			Confidential: c.Confidential, Enabled: true, RedirectURIs: c.RedirectURIs,
			Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes,
			Audiences: c.Audiences, DefaultAudiences: []string{crossExchangeDefaultA},
		}, guard)
		if err != nil {
			t.Fatal(err)
		}
	}
	conflict := postCrossExchange(s, id, secret, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
	var failure struct {
		Error       string `json:"error"`
		AccessToken string `json:"access_token"`
	}
	if conflict.Code != http.StatusConflict || json.Unmarshal(conflict.Body.Bytes(), &failure) != nil || failure.Error != "error" || failure.AccessToken != "" {
		t.Fatal("default audience race did not return the serialization-conflict contract")
	}
	afterAccess, afterRequests := crossExchangeArtifacts(t, s)
	if afterAccess != beforeAccess || afterRequests != beforeRequests {
		t.Fatal("racing default audience update left token artifacts")
	}
}

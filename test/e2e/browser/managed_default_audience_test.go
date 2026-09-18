package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestManagedDefaultAudienceLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_MANAGED_DEFAULT_AUDIENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_MANAGED_DEFAULT_AUDIENCE=1")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createCrossClientExchanger(t, admin, primary, headers, "client_credentials")
	t.Cleanup(func() { deleteCrossClientExchanger(t, admin, primary, headers, managed) })
	update := func(defaults []string) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"name": "Managed defaults E2E", "confidential": true, "enabled": true, "redirect_uris": []string{defaultRedirectURI}, "audience": []string{defaultResourceIndicator}, "default_aud": defaults, "scopes": []string{"goauthy.read", "offline_access"}, "default_scopes": []string{"goauthy.read"}, "enabled_flows": []string{"client_credentials", "authorization_code", "refresh_token"}})
		if err != nil {
			t.Fatal(err)
		}
		response := do(t, admin, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(managed.ID), bytes.NewReader(body), sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(managed.Revision, 10))))
		defer response.Body.Close()
		var metadata struct {
			Revision int64 `json:"revision"`
		}
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&metadata) != nil || metadata.Revision <= managed.Revision {
			t.Fatalf("managed defaults update status=%d", response.StatusCode)
		}
		managed.Revision = metadata.Revision
	}
	update([]string{crossClientDefaultAudienceA, defaultResourceIndicator})
	client := newBrowserClient(t)
	issue := func(base string, form url.Values) tokenResponse {
		t.Helper()
		response := tokenResponseForClient(t, client, base, managed.ID, managed.Secret, form)
		defer response.Body.Close()
		var token tokenResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&token) != nil || token.AccessToken == "" {
			t.Fatalf("managed token issuance status=%d", response.StatusCode)
		}
		return token
	}
	verify := func(token string, defaults []string) {
		t.Helper()
		for _, base := range []string{primary, secondary, tertiary} {
			claims, err := oidc.VerifyAccessToken(token, publicJWKS(t, client, base), primary, time.Now().UTC())
			want := append([]string{managed.ID}, defaults...)
			slices.Sort(want)
			slices.Sort(claims.Audience)
			if err != nil || claims.AuthorizedParty != managed.ID || !slices.Equal(claims.Audience, want) {
				t.Fatalf("managed JWT audience valid=%t", err == nil)
			}
			request, err := http.NewRequest(http.MethodPost, base+"/oidc/introspect", bytes.NewBufferString(url.Values{"token": {token}}.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.SetBasicAuth(managed.ID, managed.Secret)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			err = json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || string(body["active"]) != "true" {
				t.Fatal("managed introspection inactive")
			}
			if _, ok := body["goauthy_default_audiences"]; ok {
				t.Fatal("private snapshot leaked")
			}
			var aud []string
			if json.Unmarshal(body["aud"], &aud) != nil {
				t.Fatal("invalid introspection audience")
			}
			slices.Sort(aud)
			expected := slices.Clone(defaults)
			slices.Sort(expected)
			if !slices.Equal(aud, expected) {
				t.Fatal("introspection defaults missing or duplicated")
			}
		}
	}
	defaults := []string{crossClientDefaultAudienceA, defaultResourceIndicator}
	cc := issue(primary, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
	verify(cc.AccessToken, defaults)
	explicit := issue(secondary, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}, "resource": {defaultResourceIndicator}})
	verify(explicit.AccessToken, defaults)
	assertCrossClientExchangeRejected(t, client, primary, managed, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}, "resource": {crossClientDefaultAudienceA}}, "invalid_target")
	verifier := pkceVerifier(t)
	authorization := oidcAuthorizationURLForClient(t, primary, managed.ID, defaultRedirectURI, pkceChallenge(verifier), "managed-defaults-code", "managed-defaults-nonce", "goauthy.read offline_access")
	u, err := url.Parse(authorization)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("resource", defaultResourceIndicator)
	u.RawQuery = q.Encode()
	code, _ := loginForAuthorizationURL(t, newBrowserClient(t), u.String(), primary, secondary, username, password, "managed-defaults-code")
	coded := issue(secondary, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {defaultRedirectURI}, "code_verifier": {verifier}})
	verify(coded.AccessToken, defaults)
	refreshed := issue(tertiary, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {coded.RefreshToken}})
	verify(refreshed.AccessToken, defaults)
	update([]string{crossClientDefaultAudienceB})
	for _, token := range []string{cc.AccessToken, explicit.AccessToken, coded.AccessToken, refreshed.AccessToken} {
		for _, base := range []string{primary, secondary, tertiary} {
			assertCrossClientExchangeInactive(t, client, base, managed, token)
		}
	}
	assertCrossClientExchangeRejected(t, client, primary, managed, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}, "invalid_grant")
	revised := issue(primary, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
	verify(revised.AccessToken, []string{crossClientDefaultAudienceB})
}

package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestTokenExchangeUserClaimsAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_EXCHANGE_USER_CLAIMS") != "1" {
		t.Skip("set GOAUTHY_E2E_EXCHANGE_USER_CLAIMS=1 to run token-exchange user-claims E2E")
	}
	primary, secondary, username, password, secret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)

	original := exchangeUserClaimsMembership(t, admin, primary, headers)
	customClaimsCreateAttribute(t, admin, primary, csrf)
	t.Cleanup(func() { customClaimsDeleteAttribute(t, admin, primary, csrf) })
	customClaimsCreateScope(t, admin, primary, csrf)
	t.Cleanup(func() { customClaimsDeleteScope(t, admin, primary, csrf) })
	customClaimsAllowScope(t, admin, primary, csrf)

	sourceRole := rbacCreate(t, admin, primary, "roles", "exchange-source-role-"+randomManagedUIID(t), nil, csrf)
	currentRole := rbacCreate(t, admin, primary, "roles", "exchange-current-role-"+randomManagedUIID(t), nil, csrf)
	sourceGroup := rbacCreate(t, admin, primary, "groups", "exchange-source-group-"+randomManagedUIID(t), nil, csrf)
	currentGroup := rbacCreate(t, admin, primary, "groups", "exchange-current-group-"+randomManagedUIID(t), nil, csrf)
	t.Cleanup(func() {
		for _, entity := range []struct{ kind, id string }{{"roles", sourceRole.ID}, {"roles", currentRole.ID}, {"groups", sourceGroup.ID}, {"groups", currentGroup.ID}} {
			response := do(t, admin, http.MethodDelete, primary+"/auth/v1/"+entity.kind+"/"+entity.id, nil, headers)
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Errorf("token-exchange user-claims cleanup %s status=%d", entity.kind, response.StatusCode)
			}
		}
	})
	// Register after entity cleanup so membership is restored before the roles
	// and groups it references are removed.
	t.Cleanup(func() { exchangeUserClaimsSetMembership(t, admin, primary, headers, original) })

	exchangeUserClaimsSetMembership(t, admin, primary, headers, rbacMembership{Roles: []string{sourceRole.Name, "rauthy_admin"}, Groups: []string{sourceGroup.Name}})
	customClaimsPutValue(t, admin, primary, csrf, "source-value")
	source := exchangeUserClaimsSource(t, newBrowserClient(t), primary, secondary, username, password, secret)

	// The target must resolve this state at exchange time instead of copying the
	// source token's persisted claims.
	exchangeUserClaimsSetMembership(t, admin, primary, headers, rbacMembership{Roles: []string{currentRole.Name, "rauthy_admin"}, Groups: []string{currentGroup.Name}})
	customClaimsPutValue(t, admin, primary, csrf, "current-value")

	form := func(scope string) url.Values {
		return url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {source.AccessToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"scope":              {scope},
		}
	}
	full := exchangeUserClaimsExchange(t, newBrowserClient(t), secondary, secret, form("goauthy.read groups "+customClaimsScope))
	exchangeUserClaimsAssertJWT(t, full.AccessToken, publicJWKS(t, newBrowserClient(t), tertiary), primary, "goauthy.read groups "+customClaimsScope, []string{currentRole.Name, "rauthy_admin"}, []string{currentGroup.Name}, "current-value")
	exchangeUserClaimsAssertIntrospection(t, newBrowserClient(t), tertiary, secret, full.AccessToken, []string{currentRole.Name, "rauthy_admin"}, []string{currentGroup.Name}, "current-value")

	downscoped := exchangeUserClaimsExchange(t, newBrowserClient(t), secondary, secret, form("goauthy.read"))
	exchangeUserClaimsAssertJWT(t, downscoped.AccessToken, publicJWKS(t, newBrowserClient(t), tertiary), primary, "goauthy.read", []string{currentRole.Name, "rauthy_admin"}, nil, "")
	exchangeUserClaimsAssertIntrospection(t, newBrowserClient(t), tertiary, secret, downscoped.AccessToken, []string{currentRole.Name, "rauthy_admin"}, nil, "")
}

func exchangeUserClaimsMembership(t *testing.T, client *http.Client, base string, headers map[string]string) rbacMembership {
	t.Helper()
	response := do(t, client, http.MethodPatch, base+"/auth/v1/users/bootstrap-admin", strings.NewReader(`{"put":[],"del":[]}`), headers)
	defer response.Body.Close()
	var membership rbacMembership
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&membership)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("read token-exchange user membership status=%d decode=%v", response.StatusCode, err)
	}
	return membership
}

func exchangeUserClaimsSetMembership(t *testing.T, client *http.Client, base string, headers map[string]string, membership rbacMembership) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"put": []map[string]any{{"key": "roles", "value": membership.Roles}, {"key": "groups", "value": membership.Groups}}, "del": []string{}})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPatch, base+"/auth/v1/users/bootstrap-admin", bytes.NewReader(body), headers)
	defer response.Body.Close()
	var got rbacMembership
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&got)
	if response.StatusCode != http.StatusOK || err != nil || !sameStringSet(got.Roles, membership.Roles) || !sameStringSet(got.Groups, membership.Groups) {
		t.Fatalf("set token-exchange user membership status=%d roles=%t groups=%t decode=%v", response.StatusCode, sameStringSet(got.Roles, membership.Roles), sameStringSet(got.Groups, membership.Groups), err)
	}
}

func exchangeUserClaimsSource(t *testing.T, client *http.Client, primary, secondary, username, password, secret string) tokenResponse {
	t.Helper()
	verifier := pkceVerifier(t)
	scope := "openid goauthy.read groups " + customClaimsScope
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "exchange-user-claims-source", "exchange-user-claims-source-nonce", scope), primary, secondary, username, password, "exchange-user-claims-source")
	issued := exchangeCode(t, client, primary, secret, defaultRedirectURI, code, verifier)
	if issued.AccessToken == "" {
		t.Fatal("user-claims source issuance returned no access token")
	}
	return issued
}

func exchangeUserClaimsExchange(t *testing.T, client *http.Client, base, secret string, form url.Values) tokenResponse {
	t.Helper()
	response := tokenResponseFor(t, client, base, secret, form)
	defer response.Body.Close()
	var issued tokenResponse
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&issued)
	if response.StatusCode != http.StatusOK || err != nil || issued.AccessToken == "" || issued.RefreshToken != "" || issued.IDToken != "" {
		t.Fatalf("user-claims exchange status=%d access=%t refresh=%t id=%t decode=%v", response.StatusCode, issued.AccessToken != "", issued.RefreshToken != "", issued.IDToken != "", err)
	}
	return issued
}

func exchangeUserClaimsAssertJWT(t *testing.T, token string, keys jose.JSONWebKeySet, issuer, scope string, roles, groups []string, custom string) {
	t.Helper()
	verifyPublicAccessToken(t, token, keys, issuer, "goauthy-dev", scope, "")
	raw := rbacTokenClaims(t, token)
	rbacAssertClaimList(t, raw, "roles", roles, true)
	rbacAssertClaimList(t, raw, "groups", groups, groups != nil)
	if custom == "" {
		if _, present := raw["custom"]; present {
			t.Fatal("downscoped exchange retained custom claims")
		}
		return
	}
	customClaimsAssertNested(t, raw, custom)
}

func exchangeUserClaimsAssertIntrospection(t *testing.T, client *http.Client, base, secret, token string, roles, groups []string, custom string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var claims map[string]json.RawMessage
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&claims)
	if response.StatusCode != http.StatusOK || err != nil || string(claims["active"]) != "true" {
		t.Fatalf("user-claims introspection status=%d active=%s decode=%v", response.StatusCode, claims["active"], err)
	}
	rbacAssertClaimList(t, claims, "roles", roles, true)
	rbacAssertClaimList(t, claims, "groups", groups, groups != nil)
	if custom == "" {
		if _, present := claims["custom"]; present {
			t.Fatal("downscoped introspection retained custom claims")
		}
		return
	}
	customClaimsAssertNested(t, claims, custom)
}

func sameStringSet(left, right []string) bool {
	left, right = slices.Clone(left), slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

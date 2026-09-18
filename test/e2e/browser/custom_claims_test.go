package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	customClaimsAttribute = "e2e-employee-id"
	customClaimsScope     = "e2e-employee"
)

// TestCustomClaimsAcrossPods deliberately uses read-after-write requests to
// independently routed pods as replication barriers. It has no timing oracle.
func TestCustomClaimsAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_CUSTOM_CLAIMS") != "1" {
		t.Skip("set GOAUTHY_E2E_CUSTOM_CLAIMS=1 to run custom-claims E2E")
	}
	primary, secondary, tertiary, username, password, secret := rolesGroupsConfig(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)

	customClaimsAuthorizeRejected(t, admin, tertiary, "e2e-not-allowed")
	customClaimsCreateAttribute(t, admin, primary, csrf)
	customClaimsAssertAttribute(t, admin, secondary, true)
	customClaimsPutValue(t, admin, primary, csrf, "E-123")
	customClaimsAssertValue(t, admin, tertiary, "E-123")
	customClaimsCreateScope(t, admin, primary, csrf)
	customClaimsAssertScope(t, admin, secondary, true)
	customClaimsAllowScope(t, admin, primary, csrf)
	customClaimsAssertClientScope(t, admin, tertiary, true)
	customClaimsDynamicClient(t, newBrowserClient(t), primary, tertiary, username, password)

	issued := customClaimsIssue(t, newBrowserClient(t), primary, tertiary, primary, username, password, secret, "E-123")
	customClaimsAssertAccess(t, admin, secondary, secret, issued.AccessToken, "E-123")

	customClaimsPutValue(t, admin, primary, csrf, "E-456")
	customClaimsAssertValue(t, admin, secondary, "E-456")
	refreshed := refresh(t, admin, tertiary, secret, issued.RefreshToken)
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == issued.RefreshToken {
		t.Fatal("custom-claims refresh did not rotate its token")
	}
	customClaimsAssertID(t, refreshed.IDToken, "E-456")
	customClaimsAssertAccess(t, admin, primary, secret, refreshed.AccessToken, "E-456")
	revokeAccessToken(t, admin, tertiary, secret, refreshed.AccessToken)
	assertForwardAuthRejected(t, admin, primary, refreshed.AccessToken, username)

	customClaimsDeleteScope(t, admin, primary, csrf)
	customClaimsAssertScope(t, admin, tertiary, false)
	customClaimsAuthorizeRejected(t, admin, secondary, customClaimsScope)
	customClaimsDeleteAttribute(t, admin, primary, csrf)
	customClaimsAssertAttribute(t, admin, tertiary, false)
}

// customClaimsDynamicClient verifies that the operator's DCR policy, rather
// than client JSON, admits the custom scope and survives credential rotation.
func customClaimsDynamicClient(t *testing.T, client *http.Client, primary, secondary, username, password string) {
	t.Helper()
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if registrationToken == "" {
		t.Fatal("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN is required for dynamic custom-scope E2E")
	}
	registration := registerDynamicClient(t, primary, registrationToken, "https://rp.example.test/dynamic-custom-claims")
	if !containsString(strings.Fields(registration.Scope), customClaimsScope) {
		t.Fatalf("operator DCR policy omitted custom scope: %q", registration.Scope)
	}
	verifier := pkceVerifier(t)
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURLForClient(t, secondary, registration.ClientID, registration.RedirectURIs[0], pkceChallenge(verifier), "dynamic-custom-claims", "dynamic-custom-claims-nonce", "openid "+customClaimsScope), secondary, primary, username, password, "dynamic-custom-claims")
	tokens := exchangeCodeForClient(t, client, primary, registration.ClientID, registration.ClientSecret, registration.RedirectURIs[0], code, verifier)
	keys := publicJWKS(t, client, primary)
	claims, err := oidc.VerifyIDToken(tokens.IDToken, keys, primary, registration.ClientID, time.Now().UTC())
	if err != nil || claims.Subject == "" {
		t.Fatalf("verify dynamic custom-claims ID token: %v", err)
	}
	customClaimsAssertID(t, tokens.IDToken, "E-123")
	customClaimsAssertSignedAccessToken(t, tokens.AccessToken, keys, primary, registration.ClientID, "openid "+customClaimsScope, "E-123")
	rotated := rotateDynamicClient(t, secondary, registration, "GoAuthy Dynamic Custom Claims Updated")
	if rotated.Scope != registration.Scope {
		t.Fatalf("dynamic-client update changed operator scope policy: got=%q want=%q", rotated.Scope, registration.Scope)
	}
}

func customClaimsCreateAttribute(t *testing.T, client *http.Client, base, csrf string) {
	t.Helper()
	body := customClaimsJSON(t, map[string]any{"name": customClaimsAttribute, "desc": "E2E employee identifier", "user_editable": false})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/attr", body, rbacMutationHeaders(csrf))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create custom attribute status=%d", response.StatusCode)
	}
}

func customClaimsDeleteAttribute(t *testing.T, client *http.Client, base, csrf string) {
	t.Helper()
	response := do(t, client, http.MethodDelete, base+"/auth/v1/users/attr/"+customClaimsAttribute, nil, rbacMutationHeaders(csrf))
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete custom attribute status=%d", response.StatusCode)
	}
}

func customClaimsAssertAttribute(t *testing.T, client *http.Client, base string, present bool) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/attr", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var payload struct {
		Values []struct {
			Name string `json:"name"`
		} `json:"values"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("list custom attributes status=%d decode=%v", response.StatusCode, err)
	}
	found := false
	for _, value := range payload.Values {
		found = found || value.Name == customClaimsAttribute
	}
	if found != present {
		t.Fatalf("custom attribute present=%t want=%t", found, present)
	}
}

func customClaimsPutValue(t *testing.T, client *http.Client, base, csrf, value string) {
	t.Helper()
	body := customClaimsJSON(t, map[string]any{"values": []map[string]any{{"key": customClaimsAttribute, "value": value}}})
	response := do(t, client, http.MethodPut, base+"/auth/v1/users/bootstrap-admin/attr", body, rbacMutationHeaders(csrf))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("put custom attribute value status=%d", response.StatusCode)
	}
}

func customClaimsAssertValue(t *testing.T, client *http.Client, base, want string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/bootstrap-admin/attr", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var payload struct {
		Values []struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		} `json:"values"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("get custom attribute value status=%d decode=%v", response.StatusCode, err)
	}
	for _, value := range payload.Values {
		if value.Key == customClaimsAttribute && string(value.Value) == `"`+want+`"` {
			return
		}
	}
	t.Fatalf("custom attribute value=%#v want=%q", payload.Values, want)
}

func customClaimsCreateScope(t *testing.T, client *http.Client, base, csrf string) {
	t.Helper()
	body := customClaimsJSON(t, map[string]any{"scope": customClaimsScope, "attr_include_id": []string{customClaimsAttribute}, "attr_include_access": []string{customClaimsAttribute}, "claims_at_root": false})
	response := do(t, client, http.MethodPost, base+"/auth/v1/scopes", body, rbacMutationHeaders(csrf))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create custom scope status=%d", response.StatusCode)
	}
}

func customClaimsDeleteScope(t *testing.T, client *http.Client, base, csrf string) {
	t.Helper()
	response := do(t, client, http.MethodDelete, base+"/auth/v1/scopes/"+customClaimsScope, nil, rbacMutationHeaders(csrf))
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete custom scope status=%d", response.StatusCode)
	}
}

func customClaimsAssertScope(t *testing.T, client *http.Client, base string, present bool) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/scopes", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var scopes []struct {
		Name string `json:"scope"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&scopes)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("list custom scopes status=%d decode=%v", response.StatusCode, err)
	}
	found := false
	for _, scope := range scopes {
		found = found || scope.Name == customClaimsScope
	}
	if found != present {
		t.Fatalf("custom scope present=%t want=%t", found, present)
	}
}

func customClaimsAllowScope(t *testing.T, client *http.Client, base, csrf string) {
	t.Helper()
	policy := customClaimsClientPolicy(t, client, base)
	policy.AllowedScopes = appendUniqueScope(policy.AllowedScopes, customClaimsScope)
	body := customClaimsJSON(t, map[string]any{"allowed_scopes": policy.AllowedScopes, "default_scopes": policy.DefaultScopes})
	response := do(t, client, http.MethodPut, base+"/auth/v1/clients/goauthy-dev/scopes", body, rbacMutationHeaders(csrf))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("allow custom scope status=%d", response.StatusCode)
	}
}

type customClaimsPolicy struct {
	AllowedScopes []string `json:"allowed_scopes"`
	DefaultScopes []string `json:"default_scopes"`
}

func customClaimsClientPolicy(t *testing.T, client *http.Client, base string) customClaimsPolicy {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/clients/goauthy-dev/scopes", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var policy customClaimsPolicy
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&policy)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("get custom client scopes status=%d decode=%v", response.StatusCode, err)
	}
	return policy
}

func customClaimsAssertClientScope(t *testing.T, client *http.Client, base string, present bool) {
	t.Helper()
	policy := customClaimsClientPolicy(t, client, base)
	found := false
	for _, scope := range policy.AllowedScopes {
		found = found || scope == customClaimsScope
	}
	if found != present {
		t.Fatalf("custom client scope present=%t want=%t", found, present)
	}
}

func customClaimsIssue(t *testing.T, client *http.Client, issuerBase, authorizeBase, exchangeBase, username, password, secret, want string) tokenResponse {
	t.Helper()
	verifier := pkceVerifier(t)
	scope := "openid goauthy.read offline_access " + customClaimsScope
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURLForClient(t, authorizeBase, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "custom-claims-state", "custom-claims-nonce", scope), authorizeBase, exchangeBase, username, password, "custom-claims-state")
	tokens := exchangeCode(t, client, exchangeBase, secret, defaultRedirectURI, code, verifier)
	keys := publicJWKS(t, client, exchangeBase)
	verifyPublicIDToken(t, tokens.IDToken, keys, issuerBase)
	customClaimsAssertID(t, tokens.IDToken, want)
	customClaimsAssertSignedAccessToken(t, tokens.AccessToken, keys, issuerBase, "goauthy-dev", scope, want)
	return tokens
}

// customClaimsAssertSignedAccessToken checks the compact access token against
// the deployed public JWKS before inspecting its application claim surface.
func customClaimsAssertSignedAccessToken(t *testing.T, token string, keys jose.JSONWebKeySet, issuer, clientID, scope, want string) {
	t.Helper()
	claims := verifyPublicAccessToken(t, token, keys, issuer, clientID, scope, "")
	if claims.Subject == "" || !containsString(claims.Roles, "rauthy_admin") || claims.CustomClaims.AtRoot || len(claims.CustomClaims.Nested) != 0 || len(claims.CustomClaims.Root) != 0 || !reflect.DeepEqual(claims.CustomClaims.Values[customClaimsAttribute], json.RawMessage(`"`+want+`"`)) {
		t.Fatalf("signed custom access claims=%#v want=%q", claims, want)
	}

	// The configured scope is nested, so an attribute must not escape to the
	// root even though its signed JWT payload also has standard root claims.
	raw := rbacTokenClaims(t, token)
	if _, root := raw[customClaimsAttribute]; root {
		t.Fatalf("custom access claim escaped to JWT root: %s", raw[customClaimsAttribute])
	}
	customClaimsAssertNested(t, raw, want)
}

func customClaimsAssertID(t *testing.T, token, want string) {
	t.Helper()
	claims := rbacTokenClaims(t, token)
	customClaimsAssertNested(t, claims, want)
}

func customClaimsAssertAccess(t *testing.T, client *http.Client, base, secret, token, want string) {
	t.Helper()
	response := userInfoResponse(t, client, http.MethodGet, base, "Bearer "+token, "")
	defer response.Body.Close()
	var userinfo map[string]json.RawMessage
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&userinfo)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("custom userinfo status=%d decode=%v", response.StatusCode, err)
	}
	customClaimsAssertNested(t, userinfo, want)

	request, err := http.NewRequest(http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", secret)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var introspection map[string]json.RawMessage
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&introspection)
	if response.StatusCode != http.StatusOK || err != nil || string(introspection["active"]) != "true" {
		t.Fatalf("custom introspection status=%d active=%s decode=%v", response.StatusCode, introspection["active"], err)
	}
	customClaimsAssertNested(t, introspection, want)
}

func customClaimsAssertNested(t *testing.T, claims map[string]json.RawMessage, want string) {
	t.Helper()
	var custom map[string]json.RawMessage
	if err := json.Unmarshal(claims["custom"], &custom); err != nil || !reflect.DeepEqual(custom[customClaimsAttribute], json.RawMessage(`"`+want+`"`)) {
		t.Fatalf("nested custom claim=%s decoded=%v want=%q err=%v", claims["custom"], custom, want, err)
	}
}

func customClaimsAuthorizeRejected(t *testing.T, client *http.Client, base, denied string) {
	t.Helper()
	verifier := pkceVerifier(t)
	endpoint := oidcAuthorizationURLForClient(t, base, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "custom-claims-denied-"+denied, "custom-claims-denied-nonce", "openid "+denied)
	response := do(t, noRedirectClient(t, client.Jar), http.MethodGet, endpoint, nil, nil)
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadRequest {
		body, err := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		if err == nil && response.Header.Get("Location") == "" && string(body) == "Invalid authorization request\n" {
			return
		}
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if (response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther) || err != nil || location.Query().Get("error") != "invalid_scope" || location.Query().Get("code") != "" {
		t.Fatalf("denied custom scope=%q status=%d location=%q", denied, response.StatusCode, response.Header.Get("Location"))
	}
}

func customClaimsJSON(t *testing.T, value any) io.Reader {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(body)
}

func appendUniqueScope(values []string, scope string) []string {
	for _, value := range values {
		if value == scope {
			return values
		}
	}
	return append(values, scope)
}

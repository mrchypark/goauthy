package browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

const (
	rbacPersistRole      = "e2e-persist-role"
	rbacRenamedRole      = "e2e-persist-role-renamed"
	rbacPersistGroup     = "e2e-persist-group"
	rbacRenamedGroup     = "e2e-persist-group-renamed"
	rbacRenamedClaimRole = "e2e-claim-role-renamed"
)

type rbacEntity struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Meta map[string]any `json:"meta"`
}

type rbacMembership struct {
	Roles  []string `json:"roles"`
	Groups []string `json:"groups"`
}

func TestRolesGroupsAcrossPods(t *testing.T) {
	primary, secondary, tertiary, username, password, clientSecret := rolesGroupsConfig(t)
	switch os.Getenv("GOAUTHY_E2E_ROLES_GROUPS_PHASE") {
	case "before-replacement":
		testRolesGroupsBeforeReplacement(t, primary, secondary, tertiary, username, password, clientSecret)
	case "after-replacement":
		testRolesGroupsAfterReplacement(t, primary, secondary, tertiary, username, password, clientSecret)
	case "claims":
		testRolesGroupsClaims(t, primary, secondary, tertiary, username, password, clientSecret)
	default:
		t.Skip("set GOAUTHY_E2E_ROLES_GROUPS_PHASE to run roles/groups E2E")
	}
}

func rolesGroupsConfig(t *testing.T) (primary, secondary, tertiary, username, password, clientSecret string) {
	t.Helper()
	primary, secondary, username, password, clientSecret = browserE2EConfig(t)
	tertiary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		t.Skip("set GOAUTHY_E2E_TERTIARY_URL to run roles/groups E2E")
	}
	return primary, secondary, tertiary, username, password, clientSecret
}

func testRolesGroupsBeforeReplacement(t *testing.T, primary, secondary, tertiary, username, password, clientSecret string) {
	client, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	role := rbacCreate(t, client, primary, "roles", rbacPersistRole, map[string]any{"stage": "created"}, csrf)
	group := rbacCreate(t, client, secondary, "groups", rbacPersistGroup, map[string]any{"stage": "created"}, csrf)
	role = rbacRename(t, client, secondary, "roles", role.ID, rbacRenamedRole, map[string]any{"stage": "renamed"}, csrf)
	group = rbacRename(t, client, tertiary, "groups", group.ID, rbacRenamedGroup, map[string]any{"stage": "renamed"}, csrf)
	rbacCreateAndDelete(t, client, primary, "roles", "e2e-delete-role", csrf)
	rbacCreateAndDelete(t, client, secondary, "groups", "e2e-delete-group", csrf)
	rbacAssertListed(t, client, tertiary, "roles", role)
	rbacAssertListed(t, client, primary, "groups", group)
	rbacAssertAbsent(t, client, secondary, "roles", "e2e-delete-role")
	rbacAssertAbsent(t, client, tertiary, "groups", "e2e-delete-group")
	rbacPatchMembership(t, client, tertiary, csrf, rbacMembership{
		Roles:  []string{"e2e-claim-role", rbacRenamedRole, "rauthy_admin"},
		Groups: []string{"e2e-claim-group", rbacRenamedGroup},
	})
}

func testRolesGroupsClaims(t *testing.T, primary, secondary, tertiary, username, password, clientSecret string) {
	client, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	wantGroups := []string{"e2e-claim-group", rbacRenamedGroup}
	issued, _ := rbacIssueClaims(t, newBrowserClient(t), primary, primary, tertiary, username, password, clientSecret, true, []string{"e2e-claim-role", rbacRenamedRole, "rauthy_admin"})
	claimRole := rbacAssertListed(t, client, primary, "roles", rbacEntity{Name: "e2e-claim-role"})
	rbacRename(t, client, secondary, "roles", claimRole.ID, rbacRenamedClaimRole, map[string]any{"stage": "claim-renamed"}, csrf)
	wantRoles := []string{rbacRenamedClaimRole, rbacRenamedRole, "rauthy_admin"}
	rbacAssertIntrospectionClaims(t, client, tertiary, clientSecret, issued.AccessToken, wantRoles, wantGroups, true)
	rbacAssertRefreshedClaims(t, client, primary, tertiary, clientSecret, issued.RefreshToken, wantRoles, true)
	rbacAssertClaims(t, newBrowserClient(t), primary, primary, tertiary, username, password, clientSecret, true, wantRoles)
	rbacAssertClaims(t, newBrowserClient(t), primary, secondary, primary, username, password, clientSecret, false, wantRoles)
}

func testRolesGroupsAfterReplacement(t *testing.T, primary, secondary, tertiary, username, password, clientSecret string) {
	client, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	for _, base := range []string{primary, secondary, tertiary} {
		rbacAssertListed(t, client, base, "roles", rbacEntity{Name: rbacRenamedRole, Meta: map[string]any{"stage": "renamed"}})
		rbacAssertListed(t, client, base, "groups", rbacEntity{Name: rbacRenamedGroup, Meta: map[string]any{"stage": "renamed"}})
		rbacAssertAbsent(t, client, base, "roles", "e2e-delete-role")
		rbacAssertAbsent(t, client, base, "groups", "e2e-delete-group")
	}
	// An empty PatchOp preserves both dimensions and returns their current
	// state, so this asserts recovery without repairing missing membership.
	rbacAssertMembership(t, client, secondary, csrf, rbacMembership{
		Roles:  []string{"e2e-claim-role", rbacRenamedRole, "rauthy_admin"},
		Groups: []string{"e2e-claim-group", rbacRenamedGroup},
	})
}

func rbacAuthenticatedClient(t *testing.T, primary, secondary, username, password string) (*http.Client, string) {
	t.Helper()
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "rbac-admin", "rbac-admin-nonce"), primary, secondary, username, password, "rbac-admin")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	return client, csrf
}

func rbacCreate(t *testing.T, client *http.Client, base, kind, name string, meta map[string]any, csrf string) rbacEntity {
	t.Helper()
	entity := rbacMutation(t, client, http.MethodPost, base+"/auth/v1/"+kind, kind, name, meta, csrf)
	if entity.ID == "" || entity.Name != name || !reflect.DeepEqual(entity.Meta, meta) {
		t.Fatalf("created %s=%+v", kind, entity)
	}
	return entity
}

func rbacRename(t *testing.T, client *http.Client, base, kind, id, name string, meta map[string]any, csrf string) rbacEntity {
	t.Helper()
	entity := rbacMutation(t, client, http.MethodPut, base+"/auth/v1/"+kind+"/"+url.PathEscape(id), kind, name, meta, csrf)
	if entity.ID != id || entity.Name != name || !reflect.DeepEqual(entity.Meta, meta) {
		t.Fatalf("renamed %s=%+v", kind, entity)
	}
	return entity
}

func rbacCreateAndDelete(t *testing.T, client *http.Client, base, kind, name, csrf string) {
	t.Helper()
	entity := rbacCreate(t, client, base, kind, name, nil, csrf)
	response := do(t, client, http.MethodDelete, base+"/auth/v1/"+kind+"/"+url.PathEscape(entity.ID), nil, rbacMutationHeaders(csrf))
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete %s status=%d", kind, response.StatusCode)
	}
	rbacAssertAbsent(t, client, base, kind, name)
}

func rbacPatchMembership(t *testing.T, client *http.Client, base, csrf string, want rbacMembership) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"put": []map[string]any{{"key": "roles", "value": want.Roles}, {"key": "groups", "value": want.Groups}},
		"del": []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPatch, base+"/auth/v1/users/bootstrap-admin", bytes.NewReader(body), rbacMutationHeaders(csrf))
	defer response.Body.Close()
	var got rbacMembership
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&got); response.StatusCode != http.StatusOK || err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("membership patch status=%d got=%+v want=%+v decode=%v", response.StatusCode, got, want, err)
	}
}

func rbacAssertMembership(t *testing.T, client *http.Client, base, csrf string, want rbacMembership) {
	t.Helper()
	body := strings.NewReader(`{"put":[],"del":[]}`)
	response := do(t, client, http.MethodPatch, base+"/auth/v1/users/bootstrap-admin", body, rbacMutationHeaders(csrf))
	defer response.Body.Close()
	var got rbacMembership
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&got); response.StatusCode != http.StatusOK || err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("membership state status=%d got=%+v want=%+v decode=%v", response.StatusCode, got, want, err)
	}
}

func rbacMutation(t *testing.T, client *http.Client, method, endpoint, kind, name string, meta map[string]any, csrf string) rbacEntity {
	t.Helper()
	body, err := json.Marshal(map[string]any{strings.TrimSuffix(kind, "s"): name, "meta": meta})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, method, endpoint, bytes.NewReader(body), rbacMutationHeaders(csrf))
	defer response.Body.Close()
	var entity rbacEntity
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&entity)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("%s %s status=%d entity=%+v decode=%v", method, endpoint, response.StatusCode, entity, err)
	}
	return entity
}

func rbacMutationHeaders(csrf string) map[string]string {
	return map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
}

func rbacAssertListed(t *testing.T, client *http.Client, base, kind string, want rbacEntity) rbacEntity {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/"+kind, nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var entities []rbacEntity
	err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&entities)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("list %s status=%d decode=%v", kind, response.StatusCode, err)
	}
	for _, entity := range entities {
		if entity.Name == want.Name {
			if want.Meta != nil && !reflect.DeepEqual(entity.Meta, want.Meta) {
				t.Fatalf("listed %s metadata=%#v want=%#v", kind, entity.Meta, want.Meta)
			}
			return entity
		}
	}
	t.Fatalf("list %s lacks %q: %#v", kind, want.Name, entities)
	return rbacEntity{}
}

func rbacAssertAbsent(t *testing.T, client *http.Client, base, kind, name string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/"+kind, nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var entities []rbacEntity
	err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&entities)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("list %s after delete status=%d decode=%v", kind, response.StatusCode, err)
	}
	for _, entity := range entities {
		if entity.Name == name {
			t.Fatalf("deleted %s %q still listed", kind, name)
		}
	}
}

func rbacAssertClaims(t *testing.T, client *http.Client, issuerBase, authorizeBase, exchangeBase, username, password, clientSecret string, groupsScope bool, wantRoles []string) {
	t.Helper()
	tokens, _ := rbacIssueClaims(t, client, issuerBase, authorizeBase, exchangeBase, username, password, clientSecret, groupsScope, wantRoles)
	rbacAssertRefreshedClaims(t, client, issuerBase, exchangeBase, clientSecret, tokens.RefreshToken, wantRoles, groupsScope)
}

func rbacIssueClaims(t *testing.T, client *http.Client, issuerBase, authorizeBase, exchangeBase, username, password, clientSecret string, groupsScope bool, wantRoles []string) (tokenResponse, *http.Cookie) {
	t.Helper()
	verifier := pkceVerifier(t)
	scope := "openid goauthy.read offline_access"
	if groupsScope {
		scope += " groups"
	}
	code, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURLForClient(t, authorizeBase, "goauthy-dev", defaultRedirectURI, pkceChallenge(verifier), "rbac-claims-"+strconvBool(groupsScope), "rbac-claims-nonce-"+strconvBool(groupsScope), scope), authorizeBase, exchangeBase, username, password, "rbac-claims-"+strconvBool(groupsScope))
	tokens := exchangeCode(t, client, exchangeBase, clientSecret, defaultRedirectURI, code, verifier)
	verifyPublicIDToken(t, tokens.IDToken, publicJWKS(t, client, exchangeBase), issuerBase)
	claims := rbacTokenClaims(t, tokens.IDToken)
	rbacAssertClaimList(t, claims, "roles", wantRoles, true)
	rbacAssertClaimList(t, claims, "groups", []string{"e2e-claim-group", rbacRenamedGroup}, groupsScope)
	rbacAssertUserInfoClaims(t, client, authorizeBase, tokens.AccessToken, wantRoles, groupsScope)
	return tokens, cookie
}

func rbacAssertRefreshedClaims(t *testing.T, client *http.Client, issuerBase, exchangeBase, clientSecret, refreshToken string, wantRoles []string, groupsScope bool) {
	t.Helper()
	refreshed := refresh(t, client, exchangeBase, clientSecret, refreshToken)
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == refreshToken {
		t.Fatal("RBAC refresh did not rotate its token")
	}
	verifyPublicIDToken(t, refreshed.IDToken, publicJWKS(t, client, exchangeBase), issuerBase)
	claims := rbacTokenClaims(t, refreshed.IDToken)
	rbacAssertClaimList(t, claims, "roles", wantRoles, true)
	rbacAssertClaimList(t, claims, "groups", []string{"e2e-claim-group", rbacRenamedGroup}, groupsScope)
	rbacAssertUserInfoClaims(t, client, exchangeBase, refreshed.AccessToken, wantRoles, groupsScope)
}

func rbacAssertUserInfoClaims(t *testing.T, client *http.Client, baseURL, accessToken string, wantRoles []string, groupsScope bool) {
	t.Helper()
	response := userInfoResponse(t, client, http.MethodGet, baseURL, "Bearer "+accessToken, "")
	defer response.Body.Close()
	var info map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&info); response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("userinfo status=%d decode=%v", response.StatusCode, err)
	}
	rbacAssertClaimList(t, info, "roles", wantRoles, true)
	rbacAssertClaimList(t, info, "groups", []string{"e2e-claim-group", rbacRenamedGroup}, groupsScope)
}

func rbacAssertIntrospectionClaims(t *testing.T, client *http.Client, baseURL, clientSecret, token string, wantRoles, wantGroups []string, groupsScope bool) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var claims map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&claims); response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("RBAC introspection status=%d decode=%v", response.StatusCode, err)
	}
	if active, ok := claims["active"]; !ok || string(active) != "true" {
		t.Fatalf("RBAC introspection inactive: %v", claims)
	}
	rbacAssertClaimList(t, claims, "roles", wantRoles, true)
	rbacAssertClaimList(t, claims, "groups", wantGroups, groupsScope)
}

func strconvBool(value bool) string {
	if value {
		return "groups"
	}
	return "no-groups"
}

func rbacTokenClaims(t *testing.T, token string) map[string]json.RawMessage {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("ID token is not compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func rbacAssertClaimList(t *testing.T, claims map[string]json.RawMessage, name string, want []string, present bool) {
	t.Helper()
	raw, ok := claims[name]
	if ok != present {
		t.Fatalf("claim %q present=%t want=%t claims=%v", name, ok, present, claims)
	}
	if !present {
		return
	}
	var actual []string
	if err := json.Unmarshal(raw, &actual); err != nil || !reflect.DeepEqual(actual, want) {
		t.Fatalf("claim %q=%s decoded=%v want=%v err=%v", name, raw, actual, want, err)
	}
}

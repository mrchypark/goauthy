package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestBootstrapClientGroupRestrictionAcrossPods exercises the static-client
// restriction API through three independently routed pods. Every transition is
// acknowledged by a GET from each pod; it deliberately uses no timing oracle.
func TestBootstrapClientGroupRestrictionAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_CLIENT_GROUP_RESTRICTION") != "1" {
		t.Skip("set GOAUTHY_E2E_CLIENT_GROUP_RESTRICTION=1 to run bootstrap client group-restriction E2E")
	}
	primary, secondary, tertiary, username, password, _ := rolesGroupsConfig(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)

	const group = "e2e-client-restriction/team"
	clientRestrictionEnsureGroup(t, admin, primary, csrf, group)
	membership := clientRestrictionMembership(t, admin, tertiary, csrf)
	if !containsString(membership.Groups, group) {
		membership.Groups = append(membership.Groups, group)
		slices.Sort(membership.Groups)
		rbacPatchMembership(t, admin, primary, csrf, membership)
	}
	// A read through another pod is the deterministic replication barrier for
	// the membership write before policy evaluation begins.
	membership = clientRestrictionMembership(t, admin, secondary, csrf)
	if !containsString(membership.Groups, group) {
		t.Fatalf("matching group did not replicate to secondary: %#v", membership.Groups)
	}

	initial := clientRestrictionGet(t, admin, primary)
	matching := "e2e-client-restriction/"
	updated := clientRestrictionPut(t, admin, primary, csrf, &matching, initial.Revision)
	if updated.Revision <= initial.Revision || updated.RestrictGroupPrefix == nil || *updated.RestrictGroupPrefix != matching {
		t.Fatalf("matching restriction update: %#v", updated)
	}
	clientRestrictionAssertState(t, admin, secondary, updated)
	clientRestrictionAssertState(t, admin, tertiary, updated)

	clientRestrictionAssertCode(t, secondary, tertiary, username, password, "restriction-allowed-secondary")
	clientRestrictionAssertCode(t, tertiary, secondary, username, password, "restriction-allowed-tertiary")

	stalePrefix := "e2e-client-restriction/stale"
	stale := clientRestrictionResponse(t, admin, primary, csrf, &stalePrefix, initial.Revision)
	if stale.StatusCode != http.StatusConflict {
		stale.Body.Close()
		t.Fatalf("stale restriction update status=%d, want 409", stale.StatusCode)
	}
	stale.Body.Close()

	caseMismatch := "E2E-client-restriction/"
	updated = clientRestrictionPut(t, admin, secondary, csrf, &caseMismatch, updated.Revision)
	clientRestrictionAssertState(t, admin, tertiary, updated)
	clientRestrictionAssertDenied(t, tertiary, primary, username, password, "restriction-case-mismatch")

	literalPrefix := "e2e-client-restriction/*"
	updated = clientRestrictionPut(t, admin, tertiary, csrf, &literalPrefix, updated.Revision)
	clientRestrictionAssertState(t, admin, primary, updated)
	clientRestrictionAssertDenied(t, primary, secondary, username, password, "restriction-literal-star")

	cleared := clientRestrictionPut(t, admin, primary, csrf, nil, updated.Revision)
	if cleared.RestrictGroupPrefix != nil || cleared.Revision <= updated.Revision {
		t.Fatalf("cleared restriction: %#v", cleared)
	}
	clientRestrictionAssertState(t, admin, secondary, cleared)
	clientRestrictionAssertState(t, admin, tertiary, cleared)
	clientRestrictionAssertCode(t, secondary, tertiary, username, password, "restriction-cleared")

	clientRestrictionAssertDCRRejectsStaticField(t, primary)
}

type clientRestriction struct {
	ID                  string  `json:"client_id"`
	RestrictGroupPrefix *string `json:"restrict_group_prefix"`
	Revision            int64   `json:"revision"`
}

func clientRestrictionEnsureGroup(t *testing.T, client *http.Client, base, csrf, name string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/groups", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var groups []rbacEntity
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&groups); response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("list groups status=%d decode=%v", response.StatusCode, err)
	}
	for _, existing := range groups {
		if existing.Name == name {
			return
		}
	}
	rbacCreate(t, client, base, "groups", name, nil, csrf)
}

func clientRestrictionMembership(t *testing.T, client *http.Client, base, csrf string) rbacMembership {
	t.Helper()
	response := do(t, client, http.MethodPatch, base+"/auth/v1/users/bootstrap-admin", strings.NewReader(`{"put":[],"del":[]}`), rbacMutationHeaders(csrf))
	defer response.Body.Close()
	var membership rbacMembership
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&membership); response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("get membership status=%d membership=%+v decode=%v", response.StatusCode, membership, err)
	}
	return membership
}

func clientRestrictionGet(t *testing.T, client *http.Client, base string) clientRestriction {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/clients/goauthy-dev/login-restriction", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var restriction clientRestriction
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&restriction); response.StatusCode != http.StatusOK || err != nil || restriction.ID != "goauthy-dev" || restriction.Revision < 0 {
		t.Fatalf("get restriction status=%d restriction=%+v decode=%v", response.StatusCode, restriction, err)
	}
	return restriction
}

func clientRestrictionPut(t *testing.T, client *http.Client, base, csrf string, prefix *string, revision int64) clientRestriction {
	t.Helper()
	response := clientRestrictionResponse(t, client, base, csrf, prefix, revision)
	defer response.Body.Close()
	var restriction clientRestriction
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&restriction); response.StatusCode != http.StatusOK || err != nil || restriction.ID != "goauthy-dev" {
		t.Fatalf("put restriction status=%d restriction=%+v decode=%v", response.StatusCode, restriction, err)
	}
	return restriction
}

func clientRestrictionResponse(t *testing.T, client *http.Client, base, csrf string, prefix *string, revision int64) *http.Response {
	t.Helper()
	body, err := json.Marshal(struct {
		RestrictGroupPrefix *string `json:"restrict_group_prefix"`
		Revision            int64   `json:"revision"`
	}{RestrictGroupPrefix: prefix, Revision: revision})
	if err != nil {
		t.Fatal(err)
	}
	return do(t, client, http.MethodPut, base+"/auth/v1/clients/goauthy-dev/login-restriction", bytes.NewReader(body), rbacMutationHeaders(csrf))
}

func clientRestrictionAssertState(t *testing.T, client *http.Client, base string, want clientRestriction) {
	t.Helper()
	if got := clientRestrictionGet(t, client, base); got.ID != want.ID || got.Revision != want.Revision || !reflect.DeepEqual(got.RestrictGroupPrefix, want.RestrictGroupPrefix) {
		t.Fatalf("restriction state on %s: got=%+v want=%+v", base, got, want)
	}
}

func clientRestrictionAssertCode(t *testing.T, authorizeBase, loginBase, username, password, state string) {
	t.Helper()
	verifier := pkceVerifier(t)
	code, _ := loginForCode(t, newBrowserClient(t), authorizeBase, loginBase, defaultRedirectURI, pkceChallenge(verifier), username, password, state)
	if code == "" {
		t.Fatalf("allowed authorization issued no code for state=%q", state)
	}
}

func clientRestrictionAssertDenied(t *testing.T, authorizeBase, loginBase, username, password, state string) {
	t.Helper()
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	response := do(t, client, http.MethodGet, authorizationURL(t, authorizeBase, defaultRedirectURI, pkceChallenge(verifier), state), nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("denied authorize status=%d", response.StatusCode)
	}
	interaction := loginInteraction(t, response)
	initCookie := assertSessionCookie(t, response.Cookies(), authorizeBase)
	response.Body.Close()
	form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
	response = do(t, client, http.MethodPost, loginBase+"/auth/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		t.Fatalf("denied login status=%d", response.StatusCode)
	}
	if cookie := assertSessionCookie(t, response.Cookies(), authorizeBase); cookie.Value == initCookie.Value {
		t.Fatal("denied login did not rotate the browser session")
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || location.Query().Get("state") != state || location.Query().Get("code") != "" || location.Query().Get("error") == "" {
		t.Fatalf("denied callback location=%q err=%v", response.Header.Get("Location"), err)
	}
}

func clientRestrictionAssertDCRRejectsStaticField(t *testing.T, base string) {
	t.Helper()
	token := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if token == "" {
		return
	}
	body, err := dynamicClientRegistrationBody("https://rp.example.test/client-restriction", "DCR static field rejection")
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	request["restrict_group_prefix"] = "e2e-client-restriction/"
	body, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest, err := http.NewRequest(http.MethodPost, base+"/oidc/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Idempotency-Key", dcrIdempotencyKey(t.Name(), "/oidc/register", body))
	response, err := (&http.Client{}).Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("DCR accepted static restrict_group_prefix: status=%d", response.StatusCode)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRolesAPIKeyHasNoBrowserFallback(t *testing.T) {
	h, store, cookie, _ := membershipHTTPFixture(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "role-reader", Access: []apikey.Access{{Group: "Roles", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/v1/roles", nil)
	request.Header.Set("Authorization", "API-Key "+token)
	response := httptest.NewRecorder()
	h.Roles(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("api read status=%d body=%s", response.Code, response.Body.String())
	}

	// An authorization header is an API-key attempt, even when malformed; it
	// must not fall back to this otherwise-valid administrator session.
	request = httptest.NewRequest(http.MethodGet, "/auth/v1/roles", nil)
	request.Header.Set("Authorization", "API-Key malformed")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	h.Roles(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("malformed key fallback status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/auth/v1/roles", nil)
	request.Header.Add("Authorization", "API-Key "+token)
	request.Header.Add("Authorization", "Bearer browser-fallback-must-not-work")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	h.Roles(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("multiple authorization headers status=%d", response.Code)
	}
	_, limited, err := keys.Create(context.Background(), nil, apikey.Request{Name: "group-reader", Access: []apikey.Access{{Group: "Groups", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/auth/v1/roles", nil)
	request.Header.Set("Authorization", "API-Key "+limited)
	response = httptest.NewRecorder()
	h.Roles(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("insufficient right status=%d", response.Code)
	}
}

func TestDecodeRequestStrictlyAcceptsOnlyItsEntityShape(t *testing.T) {
	tests := []struct {
		name string
		role bool
		body string
		want string
	}{
		{"role", true, `{"role":"viewer","meta":{"source":"test"}}`, "viewer"},
		{"group", false, `{"group":"team/a","meta":null}`, "team/a"},
		{"wrong field", true, `{"group":"team"}`, ""},
		{"both names", true, `{"role":"viewer","group":"team"}`, ""},
		{"unknown", true, `{"role":"viewer","actor":"forged"}`, ""},
		{"duplicate", true, `{"role":"viewer","role":"admin"}`, ""},
		{"trailing", true, `{"role":"viewer"}{}`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/auth/v1/roles", strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json; charset=utf-8")
			got, err := decodeRequest(httptest.NewRecorder(), r, test.role)
			if (err == nil) != (test.want != "") || got.Name != test.want {
				t.Fatalf("request=%q got=%+v err=%v", test.body, got, err)
			}
		})
	}
}

func TestDecodeRequestRejectsWrongContentTypeAndLimit(t *testing.T) {
	for _, test := range []struct {
		name, contentType, body string
	}{
		{"missing type", "", `{"role":"viewer"}`},
		{"duplicate type", "application/json, application/json", `{"role":"viewer"}`},
		{"text", "text/plain", `{"role":"viewer"}`},
		{"large", "application/json", `{"role":"` + strings.Repeat("a", int(adminRequestLimit)) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/auth/v1/roles", strings.NewReader(test.body))
			if test.contentType != "" {
				r.Header.Set("Content-Type", test.contentType)
			}
			if _, err := decodeRequest(httptest.NewRecorder(), r, true); err == nil {
				t.Fatal("unexpected successful decode")
			}
		})
	}
}

func TestDecodeLoginRestrictionIsStrictAndPreservesPrefixBytes(t *testing.T) {
	valid := httptest.NewRequest(http.MethodPut, "/auth/v1/clients/bootstrap-client/login-restriction", strings.NewReader(`{"restrict_group_prefix":" team/a","revision":0}`))
	valid.Header.Set("Content-Type", "application/json")
	got, err := decodeLoginRestriction(httptest.NewRecorder(), valid)
	if err != nil || got.RestrictGroupPrefix == nil || *got.RestrictGroupPrefix != " team/a" || got.Revision != 0 {
		t.Fatalf("restriction=%+v err=%v", got, err)
	}
	for _, body := range []string{
		`{}`, `{"restrict_group_prefix":null}`, `{"restrict_group_prefix":"a","revision":0}`,
		`{"restrict_group_prefix":"team/a","revision":-1}`, `{"restrict_group_prefix":"team/a","revision":0,"extra":true}`,
		`{"restrict_group_prefix":"team/a","restrict_group_prefix":"other","revision":0}`,
	} {
		r := httptest.NewRequest(http.MethodPut, "/auth/v1/clients/bootstrap-client/login-restriction", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if _, err := decodeLoginRestriction(httptest.NewRecorder(), r); err == nil {
			t.Fatalf("accepted malformed restriction %s", body)
		}
	}
}

func TestLoginRestrictionRequiresConfiguredClientAndAdminSession(t *testing.T) {
	h, _, cookie, csrf := membershipHTTPFixture(t)
	h.bootstrapClients = map[string]struct{}{"bootstrap-client": {}}

	initial := httptest.NewRequest(http.MethodGet, "/auth/v1/clients/bootstrap-client/login-restriction", nil)
	initial.SetPathValue("id", "bootstrap-client")
	initial.AddCookie(cookie)
	initialResponse := httptest.NewRecorder()
	h.LoginRestriction(initialResponse, initial)
	if initialResponse.Code != http.StatusOK || initialResponse.Body.String() != "{\"client_id\":\"bootstrap-client\",\"restrict_group_prefix\":null,\"revision\":0}\n" {
		t.Fatalf("initial get status=%d body=%s", initialResponse.Code, initialResponse.Body.String())
	}

	put := httptest.NewRequest(http.MethodPut, "/auth/v1/clients/bootstrap-client/login-restriction", strings.NewReader(`{"restrict_group_prefix":"team/a","revision":0}`))
	put.SetPathValue("id", "bootstrap-client")
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("X-CSRF-Token", csrf)
	put.AddCookie(cookie)
	putResponse := httptest.NewRecorder()
	h.LoginRestriction(putResponse, put)
	if putResponse.Code != http.StatusOK || !strings.Contains(putResponse.Body.String(), `"revision":1`) {
		t.Fatalf("put status=%d body=%s", putResponse.Code, putResponse.Body.String())
	}
	stale := httptest.NewRequest(http.MethodPut, "/auth/v1/clients/bootstrap-client/login-restriction", strings.NewReader(`{"restrict_group_prefix":null,"revision":0}`))
	stale.SetPathValue("id", "bootstrap-client")
	stale.Header.Set("Content-Type", "application/json")
	stale.Header.Set("X-CSRF-Token", csrf)
	stale.AddCookie(cookie)
	staleResponse := httptest.NewRecorder()
	h.LoginRestriction(staleResponse, stale)
	if staleResponse.Code != http.StatusConflict {
		t.Fatalf("stale status=%d body=%s", staleResponse.Code, staleResponse.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/auth/v1/clients/bootstrap-client/login-restriction", nil)
	get.SetPathValue("id", "bootstrap-client")
	get.AddCookie(cookie)
	getResponse := httptest.NewRecorder()
	h.LoginRestriction(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), `"restrict_group_prefix":"team/a"`) {
		t.Fatalf("get status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}

	unknown := httptest.NewRequest(http.MethodGet, "/auth/v1/clients/other/login-restriction", nil)
	unknown.SetPathValue("id", "other")
	unknown.AddCookie(cookie)
	unknownResponse := httptest.NewRecorder()
	h.LoginRestriction(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown status=%d", unknownResponse.Code)
	}
}

func TestValidIDRejectsRoutingAmbiguity(t *testing.T) {
	for _, id := range []string{"", "a/b", "a\\b", "a\r", "a\n", strings.Repeat("a", 65)} {
		if validID(id) {
			t.Fatalf("accepted %q", id)
		}
	}
	if !validID("role-1") {
		t.Fatal("valid ID rejected")
	}
}

func TestDecodeMembershipPatchIsStrictAndDeterministic(t *testing.T) {
	tests := []struct {
		name                        string
		body                        string
		roles, groups               []string
		replaceRoles, replaceGroups bool
	}{
		{"put both", `{"put":[{"key":"roles","value":["viewer"]},{"key":"groups","value":["team/a"]}],"del":[]}`, []string{"viewer"}, []string{"team/a"}, true, true},
		{"delete roles", `{"put":[],"del":["roles"]}`, []string{}, nil, true, false},
		{"empty patch", `{"put":[],"del":[]}`, nil, nil, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPatch, "/auth/v1/users/user-1", strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			got, err := decodeMembershipPatch(httptest.NewRecorder(), r)
			if err != nil || !sameStrings(got.Roles, test.roles) || !sameStrings(got.Groups, test.groups) || got.ReplaceRoles != test.replaceRoles || got.ReplaceGroups != test.replaceGroups {
				t.Fatalf("patch=%+v err=%v", got, err)
			}
		})
	}
}

func TestDecodeMembershipPatchRejectsAmbiguousOrOutOfScopeInput(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"put":[],"del":[]}{}`, `{"put":[],"del":[],"put":[]}`,
		`{"put":[{"key":"roles","value":["viewer"],"value":[]}],"del":[]}`,
		`{"put":[{"key":"roles","value":["viewer"]},{"key":"roles","value":[]}],"del":[]}`,
		`{"put":[{"key":"roles","value":["viewer"]}],"del":["roles"]}`,
		`{"put":[{"key":"email","value":"x@example.test"}],"del":[]}`,
		`{"put":[{"key":"roles","value":["viewer",1]}],"del":[]}`,
		`{"put":[{"key":"groups","value":["team space"]}],"del":[]}`,
		`{"put":[],"del":["groups","groups"]}`,
	} {
		r := httptest.NewRequest(http.MethodPatch, "/auth/v1/users/user-1", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if _, err := decodeMembershipPatch(httptest.NewRecorder(), r); err == nil {
			t.Fatalf("accepted malformed patch %s", body)
		}
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestPatchUserMembershipReplacesOnlyRequestedDimensions(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	request := membershipRequest(t, cookie, csrf, `{"put":[{"key":"roles","value":["viewer"]},{"key":"groups","value":["team/a"]}],"del":[]}`)
	response := httptest.NewRecorder()
	h.PatchUserMembership(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var document membershipDocument
	if json.Unmarshal(response.Body.Bytes(), &document) != nil || document.ID != "member" || !sameStrings(document.Roles, []string{"viewer"}) || !sameStrings(document.Groups, []string{"team/a"}) {
		t.Fatalf("response=%s document=%+v", response.Body.String(), document)
	}
	principal, err := store.ResolvePrincipal(context.Background(), "member")
	if err != nil || !sameStrings(membershipNames(principal.Roles), []string{"viewer"}) || !sameStrings(membershipNames(principal.Groups), []string{"team/a"}) {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}

	clear := membershipRequest(t, cookie, csrf, `{"put":[],"del":["roles"]}`)
	cleared := httptest.NewRecorder()
	h.PatchUserMembership(cleared, clear)
	principal, err = store.ResolvePrincipal(context.Background(), "member")
	if cleared.Code != http.StatusOK || err != nil || len(principal.Roles) != 0 || !sameStrings(membershipNames(principal.Groups), []string{"team/a"}) {
		t.Fatalf("clear status=%d principal=%+v err=%v", cleared.Code, principal, err)
	}
}

func TestPatchUserMembershipRejectsUntrustedRequestsWithoutMutation(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	for _, test := range []struct {
		name   string
		body   string
		mutate func(*http.Request)
	}{
		{"missing cookie", `{"put":[{"key":"roles","value":["viewer"]}],"del":[]}`, nil},
		{"missing csrf", `{"put":[{"key":"roles","value":["viewer"]}],"del":[]}`, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
		{"cross site", `{"put":[{"key":"roles","value":["viewer"]}],"del":[]}`, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"unknown key", `{"put":[{"key":"email","value":"x"}],"del":[]}`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			useCookie := cookie
			if test.name == "missing cookie" {
				useCookie = nil
			}
			r := membershipRequest(t, useCookie, csrf, test.body)
			if test.mutate != nil {
				test.mutate(r)
			}
			response := httptest.NewRecorder()
			h.PatchUserMembership(response, r)
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			principal, err := store.ResolvePrincipal(context.Background(), "member")
			if err != nil || len(principal.Roles) != 0 || len(principal.Groups) != 0 {
				t.Fatalf("rejected request changed principal=%+v err=%v", principal, err)
			}
		})
	}
}

func TestPatchUserMembershipAllowsDelegatedGroupAdminOnly(t *testing.T) {
	h, store, _, _ := membershipHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, store.db, "delegated")
	if _, err := store.CreateGroup(ctx, "admin", "other/x", nil); err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, found, err := store.getByName(ctx, "rbac_groups", "other/x")
	if err != nil || !found {
		t.Fatalf("other group=%+v found=%t err=%v", other, found, err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "http-delegated-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?,1,0)`, Args: []any{"delegated"}},
		{SQL: `INSERT INTO rbac_user_roles (subject,role_id,granted_at_unix_ms) VALUES (?, ?, 0)`, Args: []any{"delegated", role.ID}},
		{SQL: `INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) VALUES ('member', ?, 0)`, Args: []any{other.ID}},
		{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES ('member',1,0)`, Args: nil},
	}}); err != nil {
		t.Fatal(err)
	}
	issued, err := h.browser.CreateSession(ctx, "delegated", "pwd", time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	request := membershipRequest(t, cookie, csrf, `{"put":[{"key":"groups","value":["team/a"]}],"del":[]}`)
	response := httptest.NewRecorder()
	h.PatchUserMembership(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delegated status=%d body=%s", response.Code, response.Body.String())
	}
	var document membershipDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil || !sameStrings(document.Groups, []string{"other/x", "team/a"}) {
		t.Fatalf("delegated response=%s document=%+v err=%v", response.Body.String(), document, err)
	}
	roleChange := membershipRequest(t, cookie, csrf, `{"put":[{"key":"roles","value":["viewer"]}],"del":[]}`)
	roleResponse := httptest.NewRecorder()
	h.PatchUserMembership(roleResponse, roleChange)
	if roleResponse.Code != http.StatusUnauthorized {
		t.Fatalf("delegated role status=%d body=%s", roleResponse.Code, roleResponse.Body.String())
	}
}

func membershipHTTPFixture(t *testing.T) (*Handler, *Store, *http.Cookie, string) {
	t.Helper()
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	insertActive(t, db, "member")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRole(ctx, "admin", "viewer", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateGroup(ctx, "admin", "team/a", nil); err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateSession(ctx, "admin", "pwd", time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://issuer.example.test"
	cookie, err := browser.SessionCookie(issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(store, sessions, identities, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return h, store, cookie, csrf
}

func membershipRequest(t *testing.T, cookie *http.Cookie, csrf, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPatch, "/auth/v1/users/member", bytes.NewBufferString(body))
	r.SetPathValue("subject", "member")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func membershipNames(entities []Entity) []string {
	result := make([]string, len(entities))
	for i, entity := range entities {
		result[i] = entity.Name
	}
	return result
}

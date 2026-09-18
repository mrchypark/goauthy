package claims

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
)

func TestClaimsAPIKeyRightAndNoBrowserFallback(t *testing.T) {
	ctx, store := claimsTestStore(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "scope-reader", Access: []apikey.Access{{Group: "Scopes", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(store, sessions, identities, "https://issuer.example.test")
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessions.CreateSession(ctx, "admin", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", session.Token, session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		auth []string
		want int
	}{
		{"/auth/v1/scopes", []string{"API-Key " + token}, http.StatusOK},
		{"/auth/v1/users/attr", []string{"API-Key " + token}, http.StatusForbidden},
		{"/auth/v1/scopes", []string{"API-Key bad"}, http.StatusUnauthorized},
		{"/auth/v1/scopes", []string{"Bearer browser-fallback-must-not-work"}, http.StatusUnauthorized},
		{"/auth/v1/scopes", []string{"API-Key " + token, "Bearer browser-fallback-must-not-work"}, http.StatusUnauthorized},
	} {
		r := httptest.NewRequest(http.MethodGet, test.path, nil)
		for _, value := range test.auth {
			r.Header.Add("Authorization", value)
		}
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		if strings.Contains(test.path, "/scopes") {
			h.Scopes(w, r)
		} else {
			h.Attributes(w, r)
		}
		if w.Code != test.want {
			t.Fatalf("path=%s auth=%q status=%d want=%d", test.path, test.auth, w.Code, test.want)
		}
	}
}

func TestUserAttributePutRoutesDoNotConflict(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /auth/v1/users/{first}/{second}", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("PUT /auth/v1/users/{subject}/self", func(http.ResponseWriter, *http.Request) {})

	for _, path := range []string{"/auth/v1/users/attr/employee-id", "/auth/v1/users/alice/attr", "/auth/v1/users/alice/self"} {
		req := httptest.NewRequest(http.MethodPut, path, nil)
		_, pattern := mux.Handler(req)
		if pattern == "" {
			t.Fatalf("no PUT route matched %s", path)
		}
	}
}

func TestClientScopesResponseUsesEmptyArrays(t *testing.T) {
	body, err := json.Marshal(clientScopesResponse(ClientScopes{ClientID: "client"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"allowed_scopes":[]`) || !strings.Contains(string(body), `"default_scopes":[]`) {
		t.Fatalf("client scope response = %s", body)
	}
}

func TestBootstrapClientCredentialsClaimsHTTPStrictCASAndAuth(t *testing.T) {
	ctx, store := claimsTestStore(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "client-claims-http", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Read, apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(store, sessions, identities, "https://issuer.example.test", "bootstrap-client")
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessions.CreateSession(ctx, "admin", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", session.Token, session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(session.Token)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, body string) *http.Request {
		r := httptest.NewRequest(method, "/auth/v1/clients/bootstrap-client/claims", strings.NewReader(body))
		r.SetPathValue("id", "bootstrap-client")
		return r
	}
	get := request(http.MethodGet, "")
	get.AddCookie(cookie)
	got := httptest.NewRecorder()
	h.BootstrapClientCredentialsClaims(got, get)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"claims":null`) || !strings.Contains(got.Body.String(), `"revision":0`) {
		t.Fatalf("initial status=%d body=%s", got.Code, got.Body.String())
	}
	put := request(http.MethodPut, `{"claims":{"iss":"reserved-at-policy-time"},"claims_at_root":true,"revision":0}`)
	put.AddCookie(cookie)
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("X-CSRF-Token", csrf)
	updated := httptest.NewRecorder()
	h.BootstrapClientCredentialsClaims(updated, put)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"revision":1`) || !strings.Contains(updated.Body.String(), `"iss":"reserved-at-policy-time"`) {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	for _, body := range []string{
		`{"claims":{"nested":{"x":1,"x":2}},"claims_at_root":false,"revision":1}`,
		`{"claims":{},"claims_at_root":false,"revision":1,"unknown":true}`,
		`{"claims":[],"claims_at_root":false,"revision":1}`,
	} {
		r := request(http.MethodPut, body)
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.BootstrapClientCredentialsClaims(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d", body, w.Code)
		}
	}
	api := request(http.MethodPut, `{"claims":null,"claims_at_root":false,"revision":1}`)
	api.Header.Set("Content-Type", "application/json")
	api.Header.Set("Authorization", "API-Key "+token)
	apiResult := httptest.NewRecorder()
	h.BootstrapClientCredentialsClaims(apiResult, api)
	if apiResult.Code != http.StatusOK || !strings.Contains(apiResult.Body.String(), `"claims":null`) || !strings.Contains(apiResult.Body.String(), `"revision":2`) {
		t.Fatalf("api status=%d body=%s", apiResult.Code, apiResult.Body.String())
	}
	malformed := request(http.MethodGet, "")
	malformed.AddCookie(cookie)
	malformed.Header.Add("Authorization", "Bearer must-not-fallback")
	bad := httptest.NewRecorder()
	h.BootstrapClientCredentialsClaims(bad, malformed)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("malformed auth status=%d", bad.Code)
	}
	multiple := request(http.MethodGet, "")
	multiple.AddCookie(cookie)
	multiple.Header.Add("Authorization", "API-Key "+token)
	multiple.Header.Add("Authorization", "Bearer must-not-fallback")
	multipleResult := httptest.NewRecorder()
	h.BootstrapClientCredentialsClaims(multipleResult, multiple)
	if multipleResult.Code != http.StatusUnauthorized {
		t.Fatalf("multiple auth status=%d", multipleResult.Code)
	}
}

func TestDecodeScopeStrictlyAcceptsClaimMapping(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/scopes", strings.NewReader(`{"scope":"employee","attr_include_id":["employee-id"],"claims_at_root":true}`))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	got, err := decodeScope(httptest.NewRecorder(), r)
	if err != nil || got.Name != "employee" || len(got.AttributeIncludeID) != 1 || got.AttributeIncludeID[0] != "employee-id" || !got.ClaimsAtRoot {
		t.Fatalf("scope=%+v err=%v", got, err)
	}
}

func TestCreatePermissionOnlyScopeHTTP(t *testing.T) {
	ctx, store := claimsTestStore(t)
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(store, sessions, identities, "https://issuer.example.test")
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessions.CreateSession(ctx, "admin", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie("https://issuer.example.test", session.Token, session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := browser.DeriveCSRFToken(session.Token)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/scopes", strings.NewReader(`{"scope":"permission-only","attr_include_id":[]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.Scopes(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scope":"permission-only"`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestClaimDecodersPermitUpstreamRenamePayloads(t *testing.T) {
	for _, test := range []struct {
		body   string
		decode func(http.ResponseWriter, *http.Request) error
	}{
		{`{"scope":"renamed","attr_include_id":["employee-id"]}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeScope(w, r); return err }},
		{`{"name":"renamed"}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeAttribute(w, r); return err }},
	} {
		r := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(test.body))
		r.Header.Set("Content-Type", "application/json")
		if err := test.decode(httptest.NewRecorder(), r); err != nil {
			t.Fatalf("rename payload rejected: %v", err)
		}
	}
}

func TestClaimDecodersRejectAmbiguousInput(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		body   string
		decode func(http.ResponseWriter, *http.Request) error
	}{
		{"scope unknown", "/auth/v1/scopes", `{"scope":"employee","actor":"forged"}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeScope(w, r); return err }},
		{"scope duplicate nested", "/auth/v1/scopes", `{"scope":"employee","attr_include_id":["employee-id","employee-id"]}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeScope(w, r); return err }},
		{"scope duplicate json", "/auth/v1/scopes", `{"scope":"employee","scope":"admin"}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeScope(w, r); return err }},
		{"attribute unknown", "/auth/v1/users/attr", `{"name":"employee-id","other":true}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeAttribute(w, r); return err }},
		{"attribute invalid type", "/auth/v1/users/attr", `{"name":"employee-id","typ":"uuid"}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeAttribute(w, r); return err }},
		{"values duplicate", "/auth/v1/users/user-1/attr", `{"values":[{"key":"employee-id","value":"A"},{"key":"employee-id","value":"B"}]}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeUserValues(w, r); return err }},
		{"values trailing", "/auth/v1/users/user-1/attr", `{"values":[]}{}`, func(w http.ResponseWriter, r *http.Request) error { _, err := decodeUserValues(w, r); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			if err := test.decode(httptest.NewRecorder(), r); err == nil {
				t.Fatalf("accepted %s", test.body)
			}
		})
	}
}

func TestDecodeUserValuesDeletesNullAndEmptyString(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/auth/v1/users/user-1/attr", strings.NewReader(`{"values":[{"key":"employee-id","value":"E-42"},{"key":"remove-null","value":null},{"key":"remove-empty","value":""}]}`))
	r.Header.Set("Content-Type", "application/json")
	values, err := decodeUserValues(httptest.NewRecorder(), r)
	if err != nil || len(values) != 3 || string(values["employee-id"]) != `"E-42"` || string(values["remove-null"]) != "null" || string(values["remove-empty"]) != "null" {
		t.Fatalf("values=%s err=%v", values, err)
	}
}

func TestStrictJSONRequiresOneJSONContentType(t *testing.T) {
	for _, contentType := range []string{"", "text/plain", "application/json, application/json"} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/scopes", strings.NewReader(`{"scope":"employee"}`))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if _, err := decodeScope(httptest.NewRecorder(), r); err == nil {
			t.Fatalf("accepted %q", contentType)
		}
	}
}

func TestUserValuesResponseHasStableKeyOrder(t *testing.T) {
	w := httptest.NewRecorder()
	(&Handler{}).json(w, userValuesResponse(map[string]json.RawMessage{"z": json.RawMessage(`1`), "a": json.RawMessage(`true`)}))
	if got, want := w.Body.String(), "{\"values\":[{\"key\":\"a\",\"value\":true},{\"key\":\"z\",\"value\":1}]}\n"; got != want {
		t.Fatalf("response=%s", got)
	}
}

func TestEditableAttributesResponseOmitsUnmaterializedDefault(t *testing.T) {
	w := httptest.NewRecorder()
	(&Handler{}).json(w, editableAttributesResponse([]EditableAttribute{{Attribute: Attribute{Name: "employee-id", Description: "Employee ID", Default: json.RawMessage(`"E-0"`), Type: "email"}}, {Attribute: Attribute{Name: "location", UserEditable: true}, Value: json.RawMessage(`"Seoul"`)}}))
	got := w.Body.String()
	if !strings.Contains(got, `"name":"employee-id"`) || !strings.Contains(got, `"default_value":"E-0"`) || strings.Contains(got, `"name":"employee-id","desc":"Employee ID","default_value":"E-0","typ":"email","value"`) || !strings.Contains(got, `"name":"location","value":"Seoul"`) || strings.Contains(got, `"user_editable"`) {
		t.Fatalf("response=%s", got)
	}
}

func TestEditableUserAttributesRequiresExactBrowserSubjectAndSelfPutFilters(t *testing.T) {
	ctx, store := claimsTestStore(t)
	if _, err := store.CreateAttribute(ctx, "admin", 0, Attribute{Name: "employee-id", UserEditable: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAttribute(ctx, "admin", 1, Attribute{Name: "department"}); err != nil {
		t.Fatal(err)
	}
	sessions, err := browser.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(store, sessions, identities, "https://issuer.example.test")
	if err != nil {
		t.Fatal(err)
	}
	member, err := sessions.CreateSession(ctx, "member", "pwd", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sessions.CreateSession(ctx, "admin", "pwd", time.Date(2100, time.January, 1, 1, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	memberCookie, err := browser.SessionCookie("https://issuer.example.test", member.Token, member.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	adminCookie, err := browser.SessionCookie("https://issuer.example.test", admin.Token, admin.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	editable := httptest.NewRequest(http.MethodGet, "/auth/v1/users/member/attr/editable", nil)
	editable.SetPathValue("subject", "member")
	editable.AddCookie(memberCookie)
	editable.Header.Set("Sec-Fetch-Site", "same-origin")
	editableResponse := httptest.NewRecorder()
	h.EditableUserAttributes(editableResponse, editable)
	if editableResponse.Code != http.StatusOK || !strings.Contains(editableResponse.Body.String(), `"employee-id"`) || strings.Contains(editableResponse.Body.String(), `"department"`) {
		t.Fatalf("editable status=%d body=%s", editableResponse.Code, editableResponse.Body.String())
	}
	withAuthorization := editable.Clone(ctx)
	withAuthorization.Header.Set("Authorization", "Bearer browser-fallback-must-not-work")
	withAuthorizationResponse := httptest.NewRecorder()
	h.EditableUserAttributes(withAuthorizationResponse, withAuthorization)
	if withAuthorizationResponse.Code != http.StatusUnauthorized {
		t.Fatalf("authorization fallback status=%d", withAuthorizationResponse.Code)
	}
	cross := httptest.NewRequest(http.MethodGet, "/auth/v1/users/member/attr/editable", nil)
	cross.SetPathValue("subject", "member")
	cross.AddCookie(adminCookie)
	cross.Header.Set("Sec-Fetch-Site", "same-origin")
	crossResponse := httptest.NewRecorder()
	h.EditableUserAttributes(crossResponse, cross)
	if crossResponse.Code != http.StatusForbidden {
		t.Fatalf("cross status=%d", crossResponse.Code)
	}
	csrf, err := browser.DeriveCSRFToken(member.Token)
	if err != nil {
		t.Fatal(err)
	}
	put := httptest.NewRequest(http.MethodPut, "/auth/v1/users/member/attr", strings.NewReader(`{"values":[{"key":"employee-id","value":"E-42"},{"key":"department","value":"security"}]}`))
	put.SetPathValue("subject", "member")
	put.AddCookie(memberCookie)
	put.Header.Set("Sec-Fetch-Site", "same-origin")
	put.Header.Set("X-CSRF-Token", csrf)
	put.Header.Set("Content-Type", "application/json")
	putResponse := httptest.NewRecorder()
	h.UserAttributes(putResponse, put)
	if putResponse.Code != http.StatusOK || !strings.Contains(putResponse.Body.String(), `"employee-id","value":"E-42"`) || strings.Contains(putResponse.Body.String(), `"department"`) {
		t.Fatalf("self put status=%d body=%s", putResponse.Code, putResponse.Body.String())
	}
}

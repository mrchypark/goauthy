package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAccountConnectionOAuth2StatusAndRevokeBoundaries(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "oauth2-http-lifecycle-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"oauth-http", "OAuth", "oauth2", 1, 1, "definition-generation", "[]", `["provider"]`}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"oauth-connection", "oauth-http", "member", "draft", 1, 1, "{}", "generation"}},
	}}); err != nil {
		t.Fatal(err)
	}
	memberCookie, memberCSRF := memberSession(t, store)
	statusRequest := func(cookie *http.Cookie, csrf string) *http.Request {
		r := authCollectionRequestWithPath(http.MethodGet, "/auth/v1/account/connections/oauth-http/oauth-connection/oauth2", "", cookie, csrf, map[string]string{"collection_id": "oauth-http", "connection_id": "oauth-connection"})
		return r
	}
	w := httptest.NewRecorder()
	h.AccountConnectionOAuth2Status(w, statusRequest(memberCookie, ""))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "credential") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var status struct {
		Connected bool     `json:"connected"`
		State     string   `json:"state"`
		Version   int64    `json:"version"`
		Scopes    []string `json:"scopes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.Connected || status.State != "draft" || status.Version != 0 {
		t.Fatalf("status body=%s parsed=%+v err=%v", w.Body.String(), status, err)
	}

	for name, setup := range map[string]func(*http.Request){
		"anonymous": func(r *http.Request) { r.Header.Del("Cookie") },
		"bearer":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer invalid") },
		"duplicate cookie": func(r *http.Request) {
			r.Header.Add("Cookie", r.Header.Get("Cookie"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := statusRequest(memberCookie, "")
			setup(r)
			w := httptest.NewRecorder()
			h.AccountConnectionOAuth2Status(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	insertActive(t, store.db, "other-member")
	otherCookie, _ := memberSessionFor(t, store, "other-member")
	for name, cookie := range map[string]*http.Cookie{"wrong owner": otherCookie, "missing": memberCookie} {
		t.Run(name, func(t *testing.T) {
			path := "/auth/v1/account/connections/oauth-http/oauth-unknown/oauth2"
			if name == "wrong owner" {
				path = "/auth/v1/account/connections/oauth-http/oauth-connection/oauth2"
			}
			r := authCollectionRequestWithPath(http.MethodGet, path, "", cookie, "", map[string]string{"collection_id": "oauth-http", "connection_id": strings.TrimSuffix(strings.TrimPrefix(path, "/auth/v1/account/connections/oauth-http/"), "/oauth2")})
			w := httptest.NewRecorder()
			h.AccountConnectionOAuth2Status(w, r)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	revoke := func(body string, csrf string, etag string) *httptest.ResponseRecorder {
		r := authCollectionRequestWithPath(http.MethodDelete, "/auth/v1/account/connections/oauth-http/oauth-connection/oauth2", body, memberCookie, csrf, map[string]string{"collection_id": "oauth-http", "connection_id": "oauth-connection"})
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		w := httptest.NewRecorder()
		h.AccountConnectionOAuth2Revoke(w, r)
		return w
	}
	for name, body := range map[string]string{
		"zero":      `{"version":0}`,
		"missing":   `{}`,
		"unknown":   `{"version":1,"extra":true}`,
		"duplicate": `{"version":1,"version":1}`,
	} {
		if w := revoke(body, memberCSRF, ""); w.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", name, w.Code, w.Body.String())
		}
	}
	if w := revoke(`{"version":1}`, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf status=%d", w.Code)
	}
	if w := revoke(`{"version":1}`, memberCSRF, `"1"`); w.Code != http.StatusBadRequest {
		t.Fatalf("if-match status=%d", w.Code)
	}
	if w := revoke(`{"version":1}`, memberCSRF, ""); w.Code != http.StatusConflict {
		t.Fatalf("draft revoke status=%d body=%s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		body, csrf string
		want       int
	}{
		{`{"version":1}`, "", http.StatusUnauthorized},
		{`{"version":0}`, memberCSRF, http.StatusBadRequest},
		{`{"version":1,"owner":"other"}`, memberCSRF, http.StatusBadRequest},
		{`{"version":1}`, memberCSRF, http.StatusConflict},
	} {
		r := authCollectionRequestWithPath(http.MethodPost, "/auth/v1/account/connections/oauth-http/oauth-connection/oauth2/reconnect", tc.body, memberCookie, tc.csrf, map[string]string{"collection_id": "oauth-http", "connection_id": "oauth-connection"})
		w := httptest.NewRecorder()
		h.AccountConnectionOAuth2Reconnect(w, r)
		if w.Code != tc.want {
			t.Fatalf("reconnect status=%d want=%d", w.Code, tc.want)
		}
	}
}

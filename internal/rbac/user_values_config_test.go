package rbac

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func configRequest(cookie *http.Cookie, method, body string) *http.Request {
	r := httptest.NewRequest(method, "/auth/v1/users/values_config", strings.NewReader(body))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func TestUserValuesConfigPublicAndClosedAuthorization(t *testing.T) {
	t.Parallel()
	h, store, _, keys, admin := userCreateHTTPFixture(t)
	if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{GivenName: "optional"}); err != nil {
		t.Fatal(err)
	}
	public := h.UserValuesConfigHandler(true)
	before := countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles`)
	storeDB := h.store.db
	h.store.db = nil
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(r *http.Request) { r.Header.Set("Authorization", "API-Key malformed") },
	} {
		w := httptest.NewRecorder()
		r := configRequest(nil, http.MethodGet, "")
		mutate(r)
		public.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("public config status=%d body=%s", w.Code, w.Body)
		}
		var got identity.UserValuesConfigResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, (identity.UserValuesPolicy{GivenName: "optional"}).ConfigResponse()) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("public config=%s err=%v", w.Body, err)
		}
	}
	h.store.db = storeDB
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles`) != before {
		t.Fatal("config GET mutated state")
	}
	closed := h.UserValuesConfigHandler(false)
	insertActive(t, store.db, "config-ordinary")
	ordinary := detailSession(t, h, "config-ordinary")
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		key    string
		code   int
	}{
		{"missing", nil, "", http.StatusUnauthorized},
		{"ordinary", ordinary, "", http.StatusUnauthorized},
		{"admin", admin, "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := configRequest(tc.cookie, http.MethodGet, "")
			if tc.key != "" {
				r.Header.Set("Authorization", "API-Key "+tc.key)
			}
			w := httptest.NewRecorder()
			closed.ServeHTTP(w, r)
			if w.Code != tc.code {
				t.Fatalf("status=%d want=%d", w.Code, tc.code)
			}
		})
	}
	_, readKey, err := keys.Create(context.Background(), nil, apikey.Request{Name: "config-read", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := configRequest(nil, http.MethodGet, "")
	r.Header.Set("Authorization", "API-Key "+readKey)
	w := httptest.NewRecorder()
	closed.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("read key status=%d", w.Code)
	}
	_, updateKey, err := keys.Create(context.Background(), nil, apikey.Request{Name: "config-update", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	r = configRequest(nil, http.MethodGet, "")
	r.Header.Set("Authorization", "API-Key "+updateKey)
	w = httptest.NewRecorder()
	closed.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("update-only key status=%d", w.Code)
	}
	r = configRequest(admin, http.MethodGet, "")
	r.Header.Set("Authorization", "API-Key malformed")
	w = httptest.NewRecorder()
	closed.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("malformed key with cookie status=%d", w.Code)
	}
}

func TestUserValuesConfigDelegatedAndStrictGates(t *testing.T) {
	t.Parallel()
	h, store, _, _, admin := userCreateHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, store.db, "config-delegated")
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "config-delegated-role", SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('config-delegated',?,0)`, Args: []any{role.ID}}); err != nil {
		t.Fatal(err)
	}
	delegated := detailSession(t, h, "config-delegated")
	closed := h.UserValuesConfigHandler(false)
	r := configRequest(delegated, http.MethodGet, "")
	w := httptest.NewRecorder()
	closed.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("delegated status=%d", w.Code)
	}
	for _, tc := range []struct {
		name string
		make func(*http.Request)
		code int
	}{
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 401},
		{"wrong method", func(r *http.Request) { r.Method = http.MethodPost }, 405},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=1" }, 400},
		{"body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")) }, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := configRequest(admin, http.MethodGet, "")
			tc.make(r)
			w := httptest.NewRecorder()
			closed.ServeHTTP(w, r)
			if w.Code != tc.code {
				t.Fatalf("status=%d want=%d", w.Code, tc.code)
			}
			if tc.name == "wrong method" && w.Header().Get("Allow") != http.MethodGet {
				t.Fatal("missing Allow header")
			}
		})
	}
}

func TestUserValuesConfigCapturedGuard(t *testing.T) {
	t.Parallel()
	h, store, _, keys, admin := userCreateHTTPFixture(t)
	closed := h.UserValuesConfigHandler(false)
	h.beforeUserValuesConfigRead = func() {
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "config-revoke-session", SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE subject='admin'`}); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	closed.ServeHTTP(w, configRequest(admin, http.MethodGet, ""))
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "given_name") {
		t.Fatalf("session captured guard status=%d body=%s", w.Code, w.Body)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "config-hook-key", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.beforeUserValuesConfigRead = func() {
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "config-revoke-key", SQL: `DELETE FROM api_key_access WHERE key_name='config-hook-key'`}); err != nil {
			t.Fatal(err)
		}
	}
	r := configRequest(nil, http.MethodGet, "")
	r.Header.Set("Authorization", "API-Key "+token)
	w = httptest.NewRecorder()
	closed.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "given_name") {
		t.Fatalf("key captured guard status=%d body=%s", w.Code, w.Body)
	}

	t.Run("admin role revoked", func(t *testing.T) {
		h, store, _, _, admin := userCreateHTTPFixture(t)
		h.beforeUserValuesConfigRead = func() {
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "config-revoke-admin-role", SQL: `DELETE FROM rbac_user_roles WHERE subject='admin'`}); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		h.UserValuesConfigHandler(false).ServeHTTP(w, configRequest(admin, http.MethodGet, ""))
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "given_name") {
			t.Fatalf("admin role revoke status=%d body=%s", w.Code, w.Body)
		}
	})
	t.Run("delegated role revoked", func(t *testing.T) {
		h, store, _, _, _ := userCreateHTTPFixture(t)
		insertActive(t, store.db, "config-delegated-hook")
		role, err := store.CreateRole(context.Background(), "admin", "rauthy_admin:team/*", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "config-delegated-hook-seed", SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('config-delegated-hook',?,0)`, Args: []any{role.ID}}); err != nil {
			t.Fatal(err)
		}
		cookie := detailSession(t, h, "config-delegated-hook")
		h.beforeUserValuesConfigRead = func() {
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "config-revoke-delegated-role", SQL: `DELETE FROM rbac_user_roles WHERE subject='config-delegated-hook'`}); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		h.UserValuesConfigHandler(false).ServeHTTP(w, configRequest(cookie, http.MethodGet, ""))
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "given_name") {
			t.Fatalf("delegated role revoke status=%d body=%s", w.Code, w.Body)
		}
	})
}

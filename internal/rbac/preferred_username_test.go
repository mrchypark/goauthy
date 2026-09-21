package rbac

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func preferredRequest(cookie *http.Cookie, target, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/auth/v1/users/"+target+"/self/preferred_username", strings.NewReader(body))
	r.SetPathValue("subject", target)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != nil {
		r.AddCookie(cookie)
		if token, err := browser.DeriveCSRFToken(cookie.Value); err == nil {
			r.Header.Set("X-CSRF-Token", token)
		}
	}
	return r
}

func seedPreferred(t *testing.T, store *Store, subject, email, value string) {
	t.Helper()
	var stored any = value
	if value == "" {
		stored = nil
	}
	_, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "preferred-seed-" + subject, SQL: `INSERT INTO identity_user_profiles(subject,email,preferred_username) VALUES(?,?,?)`, Args: []any{subject, email, stored}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePreferredUsernameSelfImmutableAndMutable(t *testing.T) {
	t.Parallel()
	h, store, _, _, _ := userCreateHTTPFixture(t)
	insertActive(t, store.db, "self")
	seedPreferred(t, store, "self", "self@example.test", "old")
	cookie := detailSession(t, h, "self")
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"preferred_username":"new"}`, http.StatusBadRequest},
		{`{"preferred_username":"new","force_overwrite":true}`, http.StatusForbidden},
	} {
		w := httptest.NewRecorder()
		h.UpdatePreferredUsername(w, preferredRequest(cookie, "self", tc.body))
		if w.Code != tc.code || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='self' AND preferred_username='old'`) != 1 {
			t.Fatalf("status=%d want=%d body=%s", w.Code, tc.code, w.Body)
		}
	}
	if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{PreferredUsername: (*identity.PreferredUsernamePolicy)(nil).WithImmutable(false)}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"preferred_username":null}`, `{"preferred_username":"new"}`} {
		w := httptest.NewRecorder()
		h.UpdatePreferredUsername(w, preferredRequest(cookie, "self", body))
		if w.Code != http.StatusOK {
			t.Fatalf("mutable update status=%d body=%s", w.Code, w.Body)
		}
		want := "preferred_username='new'"
		if strings.Contains(body, "null") {
			want = "preferred_username IS NULL"
		}
		if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='self' AND `+want) != 1 {
			t.Fatal("successful mutation was not persisted")
		}
	}
}

func TestUpdatePreferredUsernameAdminKeyPolicyAndDuplicate(t *testing.T) {
	t.Parallel()
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	seedPreferred(t, store, "admin", "admin@example.test", "old")
	insertActive(t, store.db, "other")
	seedPreferred(t, store, "other", "other@example.test", "taken")
	custom, err := identity.NewPreferredUsernamePolicy("required", `^[a-z]+$`, []string{"reserved"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{PreferredUsername: custom.WithImmutable(false)}); err != nil {
		t.Fatal(err)
	}
	adminPut := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.UpdatePreferredUsername(w, preferredRequest(cookie, "admin", body))
		return w
	}
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"preferred_username":null}`, 400},
		{`{"preferred_username":"reserved"}`, 406},
		{`{"preferred_username":"taken"}`, 406},
	} {
		if w := adminPut(tc.body); w.Code != tc.code {
			t.Fatalf("body=%s status=%d want=%d", tc.body, w.Code, tc.code)
		}
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "preferred-update", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := preferredRequest(nil, "admin", `{"preferred_username":"fresh","force_overwrite":true}`)
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.UpdatePreferredUsername(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("key force status=%d body=%s", w.Code, w.Body)
	}
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='admin' AND preferred_username='fresh'`) != 1 {
		t.Fatal("key mutation not persisted")
	}
	var got map[string]any
	if err := json.Unmarshal(detailRequest(h, cookie, "", "admin").Body.Bytes(), &got); err != nil || got["email"] != "admin@example.test" {
		t.Fatal("updated profile unreadable")
	}
}

func TestUpdatePreferredUsernameStrictAndHookSnapshot(t *testing.T) {
	t.Parallel()
	h, store, _, _, cookie := userCreateHTTPFixture(t)
	seedPreferred(t, store, "admin", "admin@example.test", "old")
	for _, body := range []string{`{"preferred_username":"new","unknown":1}`, `{"preferred_username":"new","preferred_username":"x"}`, `null`, `[]`, `true`, `{"Preferred_Username":"new"}`, `{"preferred_username":5}`, `{"force_overwrite":"true"}`, `{"preferred_username":""}`, `{}` + `{}`, `{"preferred_username":"` + strings.Repeat("a", 8192) + `"}`} {
		w := httptest.NewRecorder()
		h.UpdatePreferredUsername(w, preferredRequest(cookie, "admin", body))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("strict status=%d", w.Code)
		}
	}
	h.beforePreferredUsernameUpdate = func() {
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "preferred-revoke", SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE subject='admin'`}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{PreferredUsername: (*identity.PreferredUsernamePolicy)(nil).WithImmutable(false)}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.UpdatePreferredUsername(w, preferredRequest(cookie, "admin", `{"preferred_username":"new"}`))
	if w.Code != http.StatusUnauthorized || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='admin' AND preferred_username='old'`) != 1 {
		t.Fatalf("hook snapshot status=%d", w.Code)
	}
}

func TestUpdatePreferredUsernameDelegatedScopeAndRequestGates(t *testing.T) {
	t.Parallel()
	h, store, _, keys, adminCookie := userCreateHTTPFixture(t)
	if err := h.SetUserValuesPolicy(identity.UserValuesPolicy{PreferredUsername: (*identity.PreferredUsernamePolicy)(nil).WithImmutable(false)}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	insertActive(t, store.db, "delegated")
	insertActive(t, store.db, "target")
	seedPreferred(t, store, "target", "target@example.test", "")
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "preferred-delegated-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated',?,0)`, Args: []any{role.ID}},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT 'target',id,0 FROM rbac_groups WHERE name='team/a'`},
	}}); err != nil {
		t.Fatal(err)
	}
	cookie := detailSession(t, h, "delegated")
	put := func(target, body string) int {
		w := httptest.NewRecorder()
		h.UpdatePreferredUsername(w, preferredRequest(cookie, target, body))
		return w.Code
	}
	if got := put("target", `{"preferred_username":"delegated"}`); got != http.StatusOK {
		t.Fatalf("delegated initial status=%d", got)
	}
	if got := put("target", `{"preferred_username":"again"}`); got != http.StatusForbidden {
		t.Fatalf("delegated overwrite status=%d", got)
	}
	if got := put("target", `{"preferred_username":"again","force_overwrite":true}`); got != http.StatusForbidden {
		t.Fatalf("delegated force status=%d", got)
	}
	if got := put("admin", `{"preferred_username":"outside"}`); got != http.StatusForbidden {
		t.Fatalf("admin target status=%d", got)
	}
	if got := put("missing", `{"preferred_username":"outside"}`); got != http.StatusNotFound {
		t.Fatalf("missing target status=%d", got)
	}
	seedPreferred(t, store, "delegated", "delegated@example.test", "")
	for _, body := range []string{`{"preferred_username":"own-name"}`, `{"preferred_username":"own-renamed"}`} {
		if got := put("delegated", body); got != 200 {
			t.Fatalf("delegated self status=%d", got)
		}
	}
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='delegated' AND preferred_username='own-renamed'`) != 1 {
		t.Fatal("delegated self update missing")
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "preferred-read", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	request := preferredRequest(adminCookie, "admin", `{"preferred_username":"x"}`)
	request.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.UpdatePreferredUsername(w, request)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only key status=%d", w.Code)
	}
}

func TestUpdatePreferredUsernameHTTPGatesAndHook(t *testing.T) {
	t.Parallel()
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	seedPreferred(t, store, "admin", "admin@example.test", "old")
	for name, mutate := range map[string]func(*http.Request){
		"method":     func(r *http.Request) { r.Method = http.MethodPost },
		"csrf":       func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"cross-site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"bad-key":    func(r *http.Request) { r.Header.Set("Authorization", "API-Key invalid") },
		"query":      func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"media":      func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"unknown": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"preferred_username":"x","unknown":1}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := preferredRequest(cookie, "admin", `{"preferred_username":"new"}`)
			mutate(r)
			w := httptest.NewRecorder()
			h.UpdatePreferredUsername(w, r)
			want := http.StatusBadRequest
			if name == "method" {
				want = http.StatusMethodNotAllowed
			} else if name == "csrf" || name == "cross-site" || name == "bad-key" {
				want = http.StatusUnauthorized
			}
			if w.Code != want || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='admin' AND preferred_username='old'`) != 1 {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
			if name == "method" && w.Header().Get("Allow") != http.MethodPut {
				t.Fatal("missing Allow header")
			}
		})
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "preferred-hook", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.beforePreferredUsernameUpdate = func() {
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "preferred-key-revoke", SQL: `DELETE FROM api_key_access WHERE key_name='preferred-hook'`}); err != nil {
			t.Fatal(err)
		}
	}
	r := preferredRequest(nil, "admin", `{"preferred_username":"new"}`)
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.UpdatePreferredUsername(w, r)
	if w.Code != http.StatusUnauthorized || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='admin' AND preferred_username='old'`) != 1 {
		t.Fatalf("key hook status=%d", w.Code)
	}
}

func TestUpdatePreferredUsernameCapturedGuard(t *testing.T) {
	t.Parallel()
	t.Run("session revoked", func(t *testing.T) {
		h, store, _, _, cookie := userCreateHTTPFixture(t)
		insertActive(t, store.db, "session-target")
		seedPreferred(t, store, "session-target", "session-target@example.test", "")
		r := preferredRequest(cookie, "session-target", `{"preferred_username":"captured"}`)
		actor, key, ok := h.principalFor(httptest.NewRecorder(), r, true, "Users", apikey.Update, true)
		if !ok || key != nil {
			t.Fatal("failed to load admin session")
		}
		guard, args, api := h.userUpdateGuard(r, actor, key)
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "captured-session-revoke", SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE subject='admin'`}); err != nil {
			t.Fatal(err)
		}
		status, err := store.updatePreferredUsername(context.Background(), actor, "session-target", preferredUsernameRequest{PreferredUsername: strptr("captured")}, nil, guard, args, api)
		if err != nil || status != http.StatusUnauthorized || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='session-target' AND preferred_username IS NULL`) != 1 {
			t.Fatalf("status=%d err=%v", status, err)
		}
	})

	t.Run("api key rights revoked", func(t *testing.T) {
		h, store, _, keys, _ := userCreateHTTPFixture(t)
		insertActive(t, store.db, "key-target")
		seedPreferred(t, store, "key-target", "key-target@example.test", "")
		_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "captured-key", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Update}}}})
		if err != nil {
			t.Fatal(err)
		}
		r := preferredRequest(nil, "key-target", `{"preferred_username":"captured"}`)
		r.Header.Set("Authorization", "API-Key "+token)
		actor, key, ok := h.principalFor(httptest.NewRecorder(), r, true, "Users", apikey.Update, true)
		if !ok || key == nil {
			t.Fatal("failed to load API key")
		}
		guard, args, api := h.userUpdateGuard(r, actor, key)
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "captured-key-revoke", SQL: `DELETE FROM api_key_access WHERE key_name='captured-key'`}); err != nil {
			t.Fatal(err)
		}
		status, err := store.updatePreferredUsername(context.Background(), actor, "key-target", preferredUsernameRequest{PreferredUsername: strptr("captured")}, nil, guard, args, api)
		if err != nil || status != http.StatusUnauthorized || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='key-target' AND preferred_username IS NULL`) != 1 {
			t.Fatalf("status=%d err=%v", status, err)
		}
	})

	t.Run("full admin role revoked", func(t *testing.T) {
		h, store, _, _, cookie := userCreateHTTPFixture(t)
		insertActive(t, store.db, "full-target")
		seedPreferred(t, store, "full-target", "full-target@example.test", "")
		r := preferredRequest(cookie, "full-target", `{"preferred_username":"captured"}`)
		actor, key, ok := h.principalFor(httptest.NewRecorder(), r, true, "Users", apikey.Update, true)
		if !ok || key != nil {
			t.Fatal("failed to load admin session")
		}
		guard, args, api := h.userUpdateGuard(r, actor, key)
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "captured-role-revoke", SQL: `DELETE FROM rbac_user_roles WHERE subject='admin'`}); err != nil {
			t.Fatal(err)
		}
		status, err := store.updatePreferredUsername(context.Background(), actor, "full-target", preferredUsernameRequest{PreferredUsername: strptr("captured")}, nil, guard, args, api)
		if err != nil || status != http.StatusForbidden || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='full-target' AND preferred_username IS NULL`) != 1 {
			t.Fatalf("status=%d err=%v", status, err)
		}
	})

	t.Run("delegated target group removed", func(t *testing.T) {
		h, store, _, _, _ := userCreateHTTPFixture(t)
		ctx := context.Background()
		insertActive(t, store.db, "delegated-captured")
		insertActive(t, store.db, "group-target")
		seedPreferred(t, store, "group-target", "group-target@example.test", "")
		role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "captured-delegated-seed", Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated-captured',?,0)`, Args: []any{role.ID}},
			{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT 'group-target',id,0 FROM rbac_groups WHERE name='team/a'`},
		}}); err != nil {
			t.Fatal(err)
		}
		cookie := detailSession(t, h, "delegated-captured")
		r := preferredRequest(cookie, "group-target", `{"preferred_username":"captured"}`)
		actor, key, ok := h.principalFor(httptest.NewRecorder(), r, true, "Users", apikey.Update, true)
		if !ok || key != nil {
			t.Fatal("failed to load delegated session")
		}
		guard, args, api := h.userUpdateGuard(r, actor, key)
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "captured-group-revoke", SQL: `DELETE FROM rbac_user_groups WHERE subject='group-target'`}); err != nil {
			t.Fatal(err)
		}
		status, err := store.updatePreferredUsername(ctx, actor, "group-target", preferredUsernameRequest{PreferredUsername: strptr("captured")}, nil, guard, args, api)
		if err != nil || status != http.StatusPreconditionRequired || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='group-target' AND preferred_username IS NULL`) != 1 {
			t.Fatalf("status=%d err=%v", status, err)
		}
	})

	t.Run("competing name initialized", func(t *testing.T) {
		h, store, _, _, cookie := userCreateHTTPFixture(t)
		insertActive(t, store.db, "race-target")
		seedPreferred(t, store, "race-target", "race-target@example.test", "")
		insertActive(t, store.db, "race-other")
		seedPreferred(t, store, "race-other", "race-other@example.test", "")
		r := preferredRequest(cookie, "race-target", `{"preferred_username":"same-name"}`)
		actor, key, ok := h.principalFor(httptest.NewRecorder(), r, true, "Users", apikey.Update, true)
		if !ok || key != nil {
			t.Fatal("failed to load admin session")
		}
		guard, args, api := h.userUpdateGuard(r, actor, key)
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "captured-competing-name", SQL: `UPDATE identity_user_profiles SET preferred_username='same-name' WHERE subject='race-other'`}); err != nil {
			t.Fatal(err)
		}
		status, err := store.updatePreferredUsername(context.Background(), actor, "race-target", preferredUsernameRequest{PreferredUsername: strptr("same-name")}, nil, guard, args, api)
		if err != nil || status != http.StatusNotAcceptable || countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='race-target' AND preferred_username IS NULL`) != 1 {
			t.Fatalf("status=%d err=%v", status, err)
		}
	})
}

func strptr(value string) *string { return &value }

func TestUpdatePreferredUsernameMissingProfileAndWriteFailure(t *testing.T) {
	t.Parallel()
	h, store, _, _, cookie := userCreateHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, store.db, "legacy")
	put := func(body string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		h.UpdatePreferredUsername(w, preferredRequest(cookie, "legacy", body))
		if w.Code != want {
			t.Fatalf("status=%d want=%d", w.Code, want)
		}
	}
	put(`{}`, 200)
	put(`{"preferred_username":"legacy-name"}`, 409)
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='legacy'`) != 0 {
		t.Fatal("fabricated legacy email")
	}
	if err := h.userCreation.BindEmail(ctx, "legacy", "legacy@example.test"); err != nil {
		t.Fatal(err)
	}
	put(`{"preferred_username":"legacy-name"}`, 200)
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='legacy' AND email='legacy@example.test' AND preferred_username='legacy-name'`) != 1 {
		t.Fatal("recovery email profile missing")
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "preferred-profile-fields", SQL: `UPDATE identity_user_profiles SET given_name='Keep',family_name='Same',email_verified=1,user_values_json='{"tz":"UTC"}' WHERE subject='legacy'`}); err != nil {
		t.Fatal(err)
	}
	put(`{"preferred_username":"next-name","force_overwrite":true}`, 200)
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='legacy' AND email='legacy@example.test' AND preferred_username='next-name' AND given_name='Keep' AND family_name='Same' AND email_verified=1 AND user_values_json='{"tz":"UTC"}'`) != 1 {
		t.Fatal("unrelated fields changed")
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "preferred-write-failure", SQL: `CREATE TRIGGER preferred_test_abort BEFORE UPDATE ON identity_user_profiles BEGIN SELECT RAISE(ABORT,'test failure'); END`}); err != nil {
		t.Fatal(err)
	}
	put(`{"preferred_username":"failed-name","force_overwrite":true}`, 503)
	if countRows(t, store, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='legacy' AND preferred_username='next-name'`) != 1 {
		t.Fatal("failed write changed value")
	}
}

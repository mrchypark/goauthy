package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUserListHTTPPaginationAndWire(t *testing.T) {
	t.Parallel()
	h, store, cookie, _ := membershipHTTPFixture(t)
	if err := h.SetUserListThreshold(2); err != nil {
		t.Fatal(err)
	}
	request := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/users"+query, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.Users(w, r)
		return w
	}
	w := request("?page_size=1")
	if w.Code != 206 || w.Header().Get("X-User-Count") != "2" || w.Header().Get("X-Page-Size") != "2" || w.Header().Get("X-Page-Count") != "1" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v", w.Code, w.Header())
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	for _, row := range rows {
		if len(row) != 7 || string(row["email"]) != `""` || string(row["created_at"]) != "0" || string(row["last_login"]) != "null" || string(row["picture_id"]) != "null" {
			t.Fatalf("unexpected projection %v", row)
		}
		for _, field := range []string{"id", "email", "given_name", "family_name", "created_at", "last_login", "picture_id"} {
			if _, ok := row[field]; !ok {
				t.Fatalf("missing %s", field)
			}
		}
	}
	cursor := w.Header().Get("X-Continuation-Token")
	if cursor == "" {
		t.Fatal("missing cursor")
	}
	empty := request("?page_size=1&continuation_token=" + url.QueryEscape(cursor))
	if empty.Code != 206 || strings.TrimSpace(empty.Body.String()) != "[]" || empty.Header().Get("X-User-Count") != "2" || empty.Header().Get("X-Continuation-Token") != "" {
		t.Fatalf("empty status=%d headers=%v body=%s", empty.Code, empty.Header(), empty.Body.String())
	}
	if err := h.SetUserListThreshold(3); err != nil {
		t.Fatal(err)
	}
	all := request("?page_size=1&offset=65535&backwards=true")
	if all.Code != 200 || all.Header().Get("X-Page-Size") != "" || all.Body.String() != w.Body.String() {
		t.Fatalf("below threshold status=%d body=%s", all.Code, all.Body.String())
	}
	// Explicit source metadata checks include milliseconds that are not exact seconds.
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "user-list-wire-timestamps", SQL: `UPDATE identity_users SET created_at_unix_ms=1700000000123,last_login_at_unix_ms=1700000001987 WHERE subject='admin'`}); err != nil {
		t.Fatal(err)
	}
	withTimes := request("")
	var users []UserResponseSimple
	if err := json.Unmarshal(withTimes.Body.Bytes(), &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[1].ID != "admin" || users[1].CreatedAt != 1700000000 || users[1].LastLogin == nil || *users[1].LastLogin != 1700000001 {
		t.Fatalf("times=%+v", users)
	}
}

func TestUserListHTTPRechecksAuthorityAfterPreflight(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"role", "disabled", "session", "key", "grant", "delegated"} {
		t.Run(kind, func(t *testing.T) {
			h, store, cookie, _ := membershipHTTPFixture(t)
			ctx := context.Background()
			var header string
			if kind == "key" || kind == "grant" {
				keys, err := apikey.NewStore(store.db)
				if err != nil {
					t.Fatal(err)
				}
				store.BindAPIKeys(keys)
				_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "reader", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}}})
				if err != nil {
					t.Fatal(err)
				}
				header = "API-Key " + token
			}
			if kind == "delegated" {
				role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "user-list-delegated", SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES ('member',?,0)`, Args: []any{role.ID}}); err != nil {
					t.Fatal(err)
				}
				session, err := h.browser.CreateSession(ctx, "member", "pwd", time.Now().Add(time.Hour), "")
				if err != nil {
					t.Fatal(err)
				}
				cookie, err = browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
				if err != nil {
					t.Fatal(err)
				}
			}
			request := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, "/auth/v1/users", nil)
				r.AddCookie(cookie)
				if header != "" {
					r.Header.Set("Authorization", header)
				}
				w := httptest.NewRecorder()
				h.Users(w, r)
				return w
			}
			if w := request(); w.Code != 200 || w.Header().Get("X-User-Count") != "2" {
				t.Fatalf("preflight status=%d", w.Code)
			}
			called := false
			h.beforeUserListRead = func() {
				called = true
				sql := map[string]string{
					"role":      `DELETE FROM rbac_user_roles WHERE subject='admin'`,
					"disabled":  `UPDATE identity_users SET disabled=1 WHERE subject='admin'`,
					"session":   `UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE subject='admin'`,
					"key":       `DELETE FROM api_keys WHERE name='reader'`,
					"grant":     `DELETE FROM api_key_access WHERE key_name='reader'`,
					"delegated": `DELETE FROM rbac_user_roles WHERE subject='member'`,
				}[kind]
				if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "user-list-revoke", SQL: sql}); err != nil {
					t.Fatal(err)
				}
			}
			w := request()
			if !called || w.Code != 401 || w.Header().Get("X-User-Count") != "" || w.Body.String() != "Unauthorized\n" {
				t.Fatalf("after revocation status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
			}
		})
	}
}

func TestUserListHTTPNoAmbientFallback(t *testing.T) {
	t.Parallel()
	h, _, cookie, _ := membershipHTTPFixture(t)
	for _, tc := range []struct {
		header, cross string
		cookie        bool
	}{{"API-Key bad", "", true}, {"Bearer bad", "", true}, {"", "cross-site", true}, {"", "", false}} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/users", nil)
		if tc.cookie {
			r.AddCookie(cookie)
		}
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		if tc.cross != "" {
			r.Header.Set("Sec-Fetch-Site", tc.cross)
		}
		w := httptest.NewRecorder()
		h.Users(w, r)
		if w.Code != 401 {
			t.Fatalf("status=%d", w.Code)
		}
	}
}

func TestParseUserListOptions(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"page_size=0", "page_size=65536", "page_size=-1", "page_size=1&page_size=2", "offset=65536", "backwards=1", "session_state=auth", "continuation_token=", "unknown=1", "offset=1;page_size=1", "%"} {
		if _, err := parseUserListOptions(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"", "page_size=65535&offset=65535&backwards=true&session_state=Auth", "offset=0&backwards=false&session_state=Unknown"} {
		if _, err := parseUserListOptions(raw); err != nil {
			t.Errorf("rejected %q: %v", raw, err)
		}
	}
}

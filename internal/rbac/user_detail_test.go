package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func detailRequest(h *Handler, cookie *http.Cookie, key, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/auth/v1/users/"+target, nil)
	r.SetPathValue("subject", target)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if key != "" {
		r.Header.Set("Authorization", key)
	}
	w := httptest.NewRecorder()
	h.User(w, r)
	return w
}

func detailSession(t *testing.T, h *Handler, subject string) *http.Cookie {
	t.Helper()
	s, err := h.browser.CreateSession(context.Background(), subject, "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := browser.SessionCookie(h.issuer, s.Token, s.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUserDetailAuthorizationAndWire(t *testing.T) {
	t.Parallel()
	h, s, admin, _ := membershipHTTPFixture(t)
	ctx := context.Background()
	member := detailSession(t, h, "member")
	for _, tc := range []struct {
		cookie *http.Cookie
		target string
		code   int
	}{
		{admin, "admin", 200}, {admin, "member", 200}, {admin, "missing", 404},
		{member, "member", 200}, {member, "admin", 403}, {member, "missing", 403}, {nil, "member", 401},
	} {
		if w := detailRequest(h, tc.cookie, "", tc.target); w.Code != tc.code {
			t.Fatalf("target=%s got=%d body=%s", tc.target, w.Code, w.Body)
		}
	}
	w := detailRequest(h, admin, "", "member")
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != 9 || string(wire["user_values"]) != "{}" || string(wire["roles"]) != "[]" || string(wire["created_at"]) != "0" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("wire=%s headers=%v", w.Body, w.Header())
	}
	if w := detailRequest(h, admin, "Bearer bad", "admin"); w.Code != 401 {
		t.Fatalf("ambient fallback=%d", w.Code)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "detail-populate", Statements: []rhiza.SQLStatement{
		{SQL: `UPDATE identity_users SET created_at_unix_ms=1700000000123,last_login_at_unix_ms=1700000001987,user_expires_at_unix_ms=1700000005123,password_changed_at_unix_ms=1700000000123 WHERE subject='member'`},
		{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,given_name,family_name,preferred_username,user_values_json) VALUES('member','member@example.test',1,'Given','Family','preferred','{"birthdate":"2000-02-29","tz":"Asia/Seoul","unexpected":"private"}')`},
	}}); err != nil {
		t.Fatal(err)
	}
	w = detailRequest(h, admin, "", "member")
	var got UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || got.Email != "member@example.test" || !got.EmailVerified || got.CreatedAt != 1700000000 || got.LastLogin == nil || *got.LastLogin != 1700000001 || got.UserExpires == nil || *got.UserExpires != 1700000005 || got.PasswordExpires == nil || got.UserValues.PreferredUsername == nil || *got.UserValues.PreferredUsername != "preferred" || strings.Contains(w.Body.String(), "unexpected") {
		t.Fatalf("detail=%d %s", w.Code, w.Body)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "detail-expiry-null", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=NULL WHERE subject='member'`}); err != nil {
		t.Fatal(err)
	}
	w = detailRequest(h, admin, "", "member")
	if strings.Contains(w.Body.String(), `"user_expires"`) {
		t.Fatalf("NULL expiry must be omitted: %s", w.Body)
	}
}

func TestUserDetailPersistedLanguage(t *testing.T) {
	t.Parallel()
	h, s, admin, _ := membershipHTTPFixture(t)
	for _, language := range []string{"", "de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"} {
		var value any = language
		want := language
		if language == "" {
			value = nil
			want = "en"
		}
		if _, err := storage.Execute(context.Background(), s.db, rhiza.ExecuteRequest{RequestID: "detail-language-" + want + language, SQL: `UPDATE identity_users SET language=? WHERE subject='member'`, Args: []any{value}}); err != nil {
			t.Fatal(err)
		}
		w := detailRequest(h, admin, "", "member")
		var got UserResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || got.Language != want {
			t.Fatalf("language=%q status=%d body=%s", language, w.Code, w.Body)
		}
	}
}

func TestUserDetailDelegatedScopeAndCommitBarrier(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"scope", "group", "target-admin", "role", "disabled", "session", "direct-precedence", "self"} {
		t.Run(kind, func(t *testing.T) {
			h, s, admin, _ := membershipHTTPFixture(t)
			ctx := context.Background()
			insertActive(t, s.db, "delegated")
			role, err := s.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "detail-delegated", Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated',?,0)`, Args: []any{role.ID}},
				{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT 'member',id,0 FROM rbac_groups WHERE name='team/a'`},
			}})
			if err != nil {
				t.Fatal(err)
			}
			cookie := detailSession(t, h, "delegated")
			if w := detailRequest(h, cookie, "", "member"); w.Code != 200 {
				t.Fatalf("before=%d %s", w.Code, w.Body)
			}
			if w := detailRequest(h, cookie, "", "admin"); w.Code != 403 {
				t.Fatalf("protected=%d", w.Code)
			}
			if kind == "self" {
				if w := detailRequest(h, cookie, "", "delegated"); w.Code != 200 {
					t.Fatalf("self=%d", w.Code)
				}
				return
			}
			if kind == "direct-precedence" {
				if w := detailRequest(h, admin, "", "delegated"); w.Code != 200 {
					t.Fatalf("admin=%d", w.Code)
				}
				return
			}
			sql := map[string]string{
				"scope":        `UPDATE rbac_roles SET name='rauthy_admin:other/*' WHERE name='rauthy_admin:team/*'`,
				"group":        `DELETE FROM rbac_user_groups WHERE subject='member'`,
				"target-admin": `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) SELECT 'member',id,0 FROM rbac_roles WHERE name='rauthy_admin'`,
				"role":         `DELETE FROM rbac_user_roles WHERE subject='delegated'`,
				"disabled":     `UPDATE identity_users SET disabled=1 WHERE subject='delegated'`,
				"session":      `UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE subject='delegated'`,
			}[kind]
			called := false
			h.beforeUserDetailRead = func() {
				called = true
				if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "detail-barrier", SQL: sql}); err != nil {
					t.Fatal(err)
				}
			}
			want := map[string]int{"scope": 428, "group": 428, "target-admin": 403, "role": 403, "disabled": 401, "session": 401}[kind]
			w := detailRequest(h, cookie, "", "member")
			if !called || w.Code != want || w.Body.String() != http.StatusText(want)+"\n" {
				t.Fatalf("after=%d %s", w.Code, w.Body)
			}
		})
	}
}

func TestUserDetailAPIKeyRevocation(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"key", "grant"} {
		t.Run(kind, func(t *testing.T) {
			h, s, admin, _ := membershipHTTPFixture(t)
			ctx := context.Background()
			keys, err := apikey.NewStore(s.db)
			if err != nil {
				t.Fatal(err)
			}
			s.BindAPIKeys(keys)
			_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "detail-reader", Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}}})
			if err != nil {
				t.Fatal(err)
			}
			header := "API-Key " + token
			if w := detailRequest(h, admin, header, "member"); w.Code != 200 {
				t.Fatalf("before=%d %s", w.Code, w.Body)
			}
			h.beforeUserDetailRead = func() {
				sql := `DELETE FROM api_keys WHERE name='detail-reader'`
				if kind == "grant" {
					sql = `DELETE FROM api_key_access WHERE key_name='detail-reader'`
				}
				if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "detail-key-barrier", SQL: sql}); err != nil {
					t.Fatal(err)
				}
			}
			if w := detailRequest(h, admin, header, "member"); w.Code != 401 || w.Body.String() != "Unauthorized\n" {
				t.Fatalf("after=%d %s", w.Code, w.Body)
			}
		})
	}
}

func TestUserDetailExactAndWildcardScopes(t *testing.T) {
	t.Parallel()
	h, s, _, _ := membershipHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, s.db, "delegated")
	role, err := s.CreateRole(ctx, "admin", "rauthy_admin:team/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "detail-exact", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated',?,0)`, Args: []any{role.ID}},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT 'member',id,0 FROM rbac_groups WHERE name='team/a'`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := detailSession(t, h, "delegated")
	for i, tc := range []struct {
		scope string
		want  int
	}{{"team/a", 200}, {"team", 428}, {"team/*", 200}, {"team/b*", 428}, {"*", 200}} {
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("detail-scope-%d", i), SQL: `UPDATE rbac_roles SET name=? WHERE id=?`, Args: []any{"rauthy_admin:" + tc.scope, role.ID}}); err != nil {
			t.Fatal(err)
		}
		if w := detailRequest(h, cookie, "", "member"); w.Code != tc.want {
			t.Fatalf("scope=%s status=%d body=%s", tc.scope, w.Code, w.Body)
		}
	}
}

func TestUserDetailAccountTypesAndProviderAmbiguity(t *testing.T) {
	t.Parallel()
	s := userListStore(t)
	ctx := context.Background()
	for i, tc := range []struct {
		password, passkey, federated bool
		want                         string
	}{
		{false, false, false, "new"}, {true, true, false, "password"}, {false, true, false, "passkey"},
		{false, false, true, "federated"}, {true, true, true, "federated_password"}, {false, true, true, "federated_passkey"},
	} {
		password := ""
		if tc.password {
			password = "private-phc"
		}
		statements := []rhiza.SQLStatement{
			{SQL: `UPDATE identity_users SET password_phc=? WHERE subject='a'`, Args: []any{password}},
			{SQL: `DELETE FROM identity_external_links WHERE local_subject='a'`},
			{SQL: `DELETE FROM identity_webauthn_credentials WHERE subject='a'`},
			{SQL: `INSERT OR IGNORE INTO identity_webauthn_users(subject,user_handle,created_at_unix_ms) VALUES('a',?,0)`, Args: []any{strings.Repeat("h", 43)}},
		}
		if tc.passkey {
			statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_webauthn_credentials(credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES('fixture','a','fixture','{}',0,1,0,0)`})
		}
		if tc.federated {
			statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_external_links(provider_id,external_key,local_subject,linked_at_unix_ms) VALUES('provider',?,'a',0)`, Args: []any{strings.Repeat("x", 43)}})
		}
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("detail-types-%d", i), Statements: statements}); err != nil {
			t.Fatal(err)
		}
		got, _, code, err := s.detailUser(ctx, "", "a", "1", nil, true)
		if err != nil || code != 200 || got.AccountType != tc.want || (got.WebauthnUserID != nil) != tc.passkey || (got.AuthProviderID != nil) != tc.federated || got.FederationUID != nil {
			t.Fatalf("case=%d got=%+v code=%d err=%v", i, got, code, err)
		}
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "detail-second-link", SQL: `INSERT INTO identity_external_links(provider_id,external_key,local_subject,linked_at_unix_ms) VALUES('second',?,'a',0)`, Args: []any{strings.Repeat("y", 43)}}); err != nil {
		t.Fatal(err)
	}
	got, _, code, err := s.detailUser(ctx, "", "a", "1", nil, true)
	if err != nil || code != 200 || got.AuthProviderID != nil || got.FederationUID != nil || got.AccountType != "federated_passkey" {
		t.Fatalf("ambiguous provider=%+v code=%d err=%v", got, code, err)
	}
}

func TestUserDetailRequestBoundaries(t *testing.T) {
	t.Parallel()
	h, s, admin, _ := membershipHTTPFixture(t)
	for _, tc := range []struct {
		method, query, site, subject string
		want                         int
	}{
		{"GET", "", "cross-site", "admin", 401}, {"POST", "", "", "admin", 405},
		{"GET", "?unknown=1", "", "admin", 400}, {"GET", "", "", "", 400}, {"GET", "", "", strings.Repeat("a", 513), 400},
	} {
		r := httptest.NewRequest(tc.method, "/auth/v1/users/admin"+tc.query, nil)
		r.AddCookie(admin)
		r.SetPathValue("subject", tc.subject)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		w := httptest.NewRecorder()
		h.User(w, r)
		if w.Code != tc.want {
			t.Fatalf("boundary got=%d want=%d", w.Code, tc.want)
		}
	}
	keys, err := apikey.NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	s.BindAPIKeys(keys)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "wrong-reader", Access: []apikey.Access{{Group: "Roles", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	if w := detailRequest(h, admin, "API-Key "+token, "admin"); w.Code != 403 {
		t.Fatalf("wrong grant fallback=%d", w.Code)
	}
}

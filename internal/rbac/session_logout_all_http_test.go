package rbac

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLogoutAllSessionsHTTPAdminAndGates(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "logout-all-seed", SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('logout-a','member','pwd',1,4102444800000,1),('logout-b','member','pwd',1,4102444800000,1)`}); err != nil {
		t.Fatal(err)
	}
	request := func(method, query, body, auth, csrfToken string, c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/auth/v1/sessions"+query, strings.NewReader(body))
		if c != nil {
			r.AddCookie(c)
		}
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		if csrfToken != "" {
			r.Header.Set("X-CSRF-Token", csrfToken)
		}
		w := httptest.NewRecorder()
		h.LogoutAllSessions(w, r)
		return w
	}
	if w := request(http.MethodDelete, "", "", "", csrf, cookie); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("admin status=%d body=%s", w.Code, w.Body)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NULL`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("live sessions=%#v err=%v", rows.Rows, err)
	}
}

func TestLogoutAllSessionsHTTPFreshGates(t *testing.T) {
	for _, tc := range []struct {
		name, method, suffix, body string
		csrf, site                 string
		want                       int
	}{{"wrong method", http.MethodGet, "", "", "csrf", "", 405}, {"no csrf", http.MethodDelete, "", "", "", "", 401}, {"cross site", http.MethodDelete, "", "", "csrf", "cross-site", 401}, {"query", http.MethodDelete, "?x=1", "", "csrf", "", 400}, {"body", http.MethodDelete, "", "{}", "csrf", "", 400}} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, cookie, csrf := membershipHTTPFixture(t)
			r := httptest.NewRequest(tc.method, "/auth/v1/sessions"+tc.suffix, strings.NewReader(tc.body))
			r.AddCookie(cookie)
			if tc.csrf != "" {
				r.Header.Set("X-CSRF-Token", csrf)
			}
			if tc.site != "" {
				r.Header.Set("Sec-Fetch-Site", tc.site)
			}
			w := httptest.NewRecorder()
			h.LogoutAllSessions(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
			if tc.want == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodDelete {
				t.Fatal("missing Allow: DELETE")
			}
			count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NULL`, "admin", 1)
		})
	}
}

func TestLogoutAllSessionsHTTPKeyAndNoFallback(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, del, err := keys.Create(context.Background(), nil, apikey.Request{Name: "logout-all-delete", Access: []apikey.Access{{Group: "Sessions", AccessRights: []apikey.Right{apikey.Delete}}}})
	if err != nil {
		t.Fatal(err)
	}
	_, read, err := keys.Create(context.Background(), nil, apikey.Request{Name: "logout-all-read", Access: []apikey.Access{{Group: "Sessions", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions", nil)
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		h.LogoutAllSessions(w, r)
		return w
	}
	if w := request("API-Key " + read); w.Code != 403 {
		t.Fatalf("read status=%d", w.Code)
	}
	count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NULL`, "admin", 1)
	r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions", nil)
	r.Header.Set("Authorization", "Bearer bad")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.LogoutAllSessions(w, r)
	if w.Code != 401 {
		t.Fatalf("fallback status=%d", w.Code)
	}
	count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NULL`, "admin", 1)
	for range 2 {
		if w := request("API-Key " + del); w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Fatalf("key status=%d", w.Code)
		}
	}
	count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NULL`, "admin", 0)
}

func TestLogoutAllSessionsHTTPDelegatedAndReaderDenied(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	ctx := context.Background()
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "logout-all-delegated-role", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('member',?,0)`, Args: []any{role.ID}},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT 'member',id,0 FROM rbac_groups WHERE name='team/a'`},
	}}); err != nil {
		t.Fatal(err)
	}
	session, err := h.browser.CreateSession(ctx, "member", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	dc, err := browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	dcsrf, err := browser.DeriveCSRFToken(session.Token)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions", nil)
	r.AddCookie(dc)
	r.Header.Set("X-CSRF-Token", dcsrf)
	w := httptest.NewRecorder()
	h.LogoutAllSessions(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("delegated status=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions", iotest.ErrReader(errors.New("input unavailable")))
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	w = httptest.NewRecorder()
	h.LogoutAllSessions(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reader status=%d", w.Code)
	}
	for _, subject := range []string{"admin", "member"} {
		count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NULL`, subject, 1)
	}
	count(t, store.db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE ?`, 1, 0)
}

func TestLogoutAllSessionsHTTPEntropyFailurePreservesState(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	store.random = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	h.LogoutAllSessions(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", w.Code)
	}
	rows, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM browser_sessions WHERE revoked_at_unix_ms IS NULL`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] == int64(0) {
		t.Fatalf("state changed rows=%#v err=%v", rows.Rows, err)
	}
}

package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestEventsTestCreatesOnlyForCreateAuthority(t *testing.T) {
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	ctx := context.Background()
	_, createToken, err := keys.Create(ctx, nil, apikey.Request{Name: "events-create", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Create}}}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(auth, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/events/test", strings.NewReader(body))
		r.RemoteAddr = "198.51.100.4:4321"
		r.Header.Set("Authorization", auth)
		if cookie != nil && auth == "" {
			r.AddCookie(cookie)
			r.Header.Set("X-CSRF-Token", csrfForTest(t, cookie.Value))
		}
		w := httptest.NewRecorder()
		h.EventsTest(w, r)
		return w
	}
	if w := call("API-Key "+createToken, ""); w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*),MAX(ip) FROM event_log WHERE typ='Test'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != "198.51.100.4" {
		t.Fatalf("events=%v err=%v", rows.Rows, err)
	}
	_, readToken, err := keys.Create(ctx, nil, apikey.Request{Name: "events-read", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	if w := call("API-Key "+readToken, ""); w.Code != http.StatusForbidden {
		t.Fatalf("read-only status=%d", w.Code)
	}
	for _, tc := range []struct {
		name, method, body, query string
		want                      int
	}{{"wrong method", http.MethodGet, "", "", 405}, {"body", http.MethodPost, "x", "", 400}, {"query", http.MethodPost, "", "?x=1", 400}} {
		r := httptest.NewRequest(tc.method, "/auth/v1/events/test"+tc.query, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "API-Key "+createToken)
		w := httptest.NewRecorder()
		h.EventsTest(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s status=%d", tc.name, w.Code)
		}
	}
	if countRows(t, store, `SELECT COUNT(*) FROM event_log`) != 1 || countRows(t, store, `SELECT COUNT(*) FROM event_log_order`) != 1 {
		t.Fatal("rejected requests appended records")
	}
}

func csrfForTest(t *testing.T, value string) string {
	token, err := browser.DeriveCSRFToken(value)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestEventsTestGuardRejectsRevokedKeyBeforeInsert(t *testing.T) {
	h, store, _, keys, _ := userCreateHTTPFixture(t)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "events-hook", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Create}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.beforeEventCreate = func() {
		h.beforeEventCreate = nil
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "events-hook-revoke", SQL: `DELETE FROM api_key_access WHERE key_name='events-hook'`}); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/events/test", nil)
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.EventsTest(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	rows, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ=?`, Args: []any{string(eventlog.Test)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("event rows=%v err=%v", rows.Rows, err)
	}
	if countRows(t, store, `SELECT COUNT(*) FROM event_log_order`) != 0 {
		t.Fatal("revoked key appended sequence")
	}
}

func TestEventsTestBrowserCommitRevocation(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"role", `DELETE FROM rbac_user_roles WHERE subject='admin'`},
		{"session", `UPDATE browser_sessions SET revoked_at_unix_ms=1700000000000 WHERE subject='admin'`},
		{"expiry", `UPDATE identity_users SET user_expires_at_unix_ms=1700000000000 WHERE subject='admin'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, _, _, cookie := userCreateHTTPFixture(t)
			h.beforeEventCreate = func() {
				h.beforeEventCreate = nil
				if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "event-browser-revoke-" + tc.name, SQL: tc.sql}); err != nil {
					t.Fatal(err)
				}
			}
			r := httptest.NewRequest(http.MethodPost, "/auth/v1/events/test", nil)
			r.AddCookie(cookie)
			r.Header.Set("X-CSRF-Token", csrfForTest(t, cookie.Value))
			w := httptest.NewRecorder()
			h.EventsTest(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			rows, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ=?`, Args: []any{string(eventlog.Test)}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || rows.Rows[0][0] != int64(0) {
				t.Fatalf("rows=%v err=%v", rows.Rows, err)
			}
			if countRows(t, store, `SELECT COUNT(*) FROM event_log_order`) != 0 {
				t.Fatal("revoked browser appended sequence")
			}
		})
	}
}

func TestEventsTestBrowserAuthAndCSRFFailures(t *testing.T) {
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	_, revoked, err := keys.Create(context.Background(), nil, apikey.Request{Name: "revoked-event-creator", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Create}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(context.Background(), nil, "revoked-event-creator"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, auth   string
		csrf, cookie bool
		want         int
	}{
		{"anonymous", "", false, false, http.StatusUnauthorized},
		{"missing csrf", "", false, true, http.StatusUnauthorized},
		{"malformed api key", "API-Key bad", true, true, http.StatusUnauthorized},
		{"revoked api key", "API-Key " + revoked, true, true, http.StatusUnauthorized},
		{"cross-site", "", true, true, http.StatusUnauthorized},
	} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/events/test", nil)
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		if tc.cookie {
			r.AddCookie(cookie)
		}
		if tc.name == "cross-site" {
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		if tc.csrf {
			r.Header.Set("X-CSRF-Token", csrfForTest(t, cookie.Value))
		}
		w := httptest.NewRecorder()
		h.EventsTest(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s status=%d", tc.name, w.Code)
		}
	}
	if countRows(t, store, `SELECT COUNT(*) FROM event_log`) != 0 || countRows(t, store, `SELECT COUNT(*) FROM event_log_order`) != 0 {
		t.Fatal("unauthorized request appended records")
	}
}

func TestEventsTestDelegatedGroupAdminIsReadOnly(t *testing.T) {
	h, store, _, _, _ := userCreateHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, store.db, "delegated-events")
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "events-delegated-role", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_principal_versions(subject,revision,updated_at_unix_ms) VALUES(?,1,0)`, Args: []any{"delegated-events"}},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES(?,?,0)`, Args: []any{"delegated-events", role.ID}},
	}}); err != nil {
		t.Fatal(err)
	}
	issued, err := h.browser.CreateSession(ctx, "delegated-events", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if direct, err := store.IsAdmin(ctx, "delegated-events"); err != nil || direct {
		t.Fatalf("direct admin=%v err=%v", direct, err)
	}
	if delegated, err := store.isDelegatedAdmin(ctx, "delegated-events"); err != nil || !delegated {
		t.Fatalf("delegated admin=%v err=%v", delegated, err)
	}
	e := eventlog.Creation("delegated-event", "delegated@example.test", "192.0.2.4", false, time.UnixMilli(1_800_000_000_000))
	stmt, err := e.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delegated-event-seed", Statements: []rhiza.SQLStatement{stmt}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(`{"from":1719784800,"until":4102444800,"level":"info"}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.EventsQuery(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), e.ID) {
		t.Fatalf("delegated read status=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/auth/v1/events/test", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrfForTest(t, cookie.Value))
	w = httptest.NewRecorder()
	h.EventsTest(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("delegated create status=%d", w.Code)
	}
	if countRows(t, store, `SELECT COUNT(*) FROM event_log`) != 1 || countRows(t, store, `SELECT COUNT(*) FROM event_log_order`) != 1 {
		t.Fatal("delegated creator appended records")
	}
}

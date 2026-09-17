package rbac

import (
	"context"
	"crypto/rand"
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

func TestDeleteSessionByIDHTTPAdminAndBoundaries(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	ctx := context.Background()
	sid := deleteSessionSID(t, 9)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delete-http-seed", SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?,?,1,?,1)`, Args: []any{sid, "member", "pwd", 4102444800000}}); err != nil {
		t.Fatal(err)
	}
	request := func(id string, c *http.Cookie, token, query, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+id+query, strings.NewReader(body))
		r.SetPathValue("session_id", id)
		if c != nil {
			r.AddCookie(c)
		}
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		w := httptest.NewRecorder()
		h.DeleteSessionByID(w, r)
		return w
	}
	if w := request(sid, cookie, csrf, "", ""); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		id   string
		code int
	}{{deleteSessionSID(t, 8), 404}, {"bad", 404}} {
		if w := request(tc.id, cookie, csrf, "", ""); w.Code != tc.code {
			t.Fatalf("id=%s status=%d", tc.id, w.Code)
		}
	}
	if w := request(sid, cookie, "", "", ""); w.Code != 401 {
		t.Fatalf("csrf status=%d", w.Code)
	}
	if w := request(sid, cookie, csrf, "?x=1", ""); w.Code != 400 {
		t.Fatalf("query status=%d", w.Code)
	}
	if w := request(sid, cookie, csrf, "", "{}"); w.Code != 400 {
		t.Fatalf("body status=%d", w.Code)
	}
}

func TestDeleteSessionByIDHTTPAPIKeyAndNoFallback(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "session-delete-http", Access: []apikey.Access{{Group: "Sessions", AccessRights: []apikey.Right{apikey.Delete}}}})
	if err != nil {
		t.Fatal(err)
	}
	sid := deleteSessionSID(t, 7)
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "delete-http-key-seed", SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?,?,1,?,1)`, Args: []any{sid, "member", "pwd", 4102444800000}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+sid, nil)
	r.SetPathValue("session_id", sid)
	r.Header.Set("Authorization", "Bearer bad")
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	h.DeleteSessionByID(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("fallback status=%d", w.Code)
	}
	count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, sid, 1)
	r = httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+sid, nil)
	r.SetPathValue("session_id", sid)
	r.Header.Set("Authorization", "API-Key "+token)
	w = httptest.NewRecorder()
	h.DeleteSessionByID(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("key status=%d body=%s", w.Code, w.Body)
	}
}

func TestDeleteSessionByIDHTTPSelfReaderDelegatedAndRandomFailure(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	ctx := context.Background()
	self, err := browser.CanonicalTokenDigest(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+self, nil)
	r.SetPathValue("session_id", self)
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	h.DeleteSessionByID(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("self delete status=%d body=%s", w.Code, w.Body)
	}
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, readToken, err := keys.Create(ctx, nil, apikey.Request{Name: "session-reader-only", Access: []apikey.Access{{Group: "Sessions", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	sid := deleteSessionSID(t, 6)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delete-http-reader-seed", SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?,?,1,?,1)`, Args: []any{sid, "member", "pwd", 4102444800000}}); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+sid, nil)
	r.SetPathValue("session_id", sid)
	r.Header.Set("Authorization", "API-Key "+readToken)
	w = httptest.NewRecorder()
	h.DeleteSessionByID(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("reader status=%d body=%s", w.Code, w.Body)
	}
	count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=?`, sid, 1)
	role, err := store.CreateRole(ctx, "admin", "rauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "delete-http-delegated-role", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('member',?,0)`, Args: []any{role.ID}},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT 'member',id,0 FROM rbac_groups WHERE name='team/a'`},
	}}); err != nil {
		t.Fatal(err)
	}
	delegated, err := h.browser.CreateSession(ctx, "member", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	dc, err := browser.SessionCookie(h.issuer, delegated.Token, delegated.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	dcsrf, _ := browser.DeriveCSRFToken(delegated.Token)
	r = httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+sid, nil)
	r.SetPathValue("session_id", sid)
	r.AddCookie(dc)
	r.Header.Set("X-CSRF-Token", dcsrf)
	w = httptest.NewRecorder()
	h.DeleteSessionByID(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("delegated status=%d body=%s", w.Code, w.Body)
	}
	store.random = func([]byte) (int, error) { return 0, errors.New("random unavailable") }
	t.Cleanup(func() { store.random = rand.Read })
	admin2, err := h.browser.CreateSession(ctx, "admin", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	ac2, err := browser.SessionCookie(h.issuer, admin2.Token, admin2.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	csrf2, _ := browser.DeriveCSRFToken(admin2.Token)
	r = httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+sid, iotest.ErrReader(errors.New("reader unavailable")))
	r.SetPathValue("session_id", sid)
	r.AddCookie(ac2)
	r.Header.Set("X-CSRF-Token", csrf2)
	w = httptest.NewRecorder()
	h.DeleteSessionByID(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reader failure status=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/id/"+sid, nil)
	r.SetPathValue("session_id", sid)
	r.AddCookie(ac2)
	r.Header.Set("X-CSRF-Token", csrf2)
	w = httptest.NewRecorder()
	h.DeleteSessionByID(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("random failure status=%d", w.Code)
	}
	count(t, store.db, `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, sid, 0)
	count(t, store.db, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND revoked_at_unix_ms IS NULL`, sid, 1)
}

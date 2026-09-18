package rbac

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestEventsQueryKeyAndBrowserAdmin(t *testing.T) {
	h, store, _, keys, cookie := userCreateHTTPFixture(t)
	ctx := context.Background()
	at := time.UnixMilli(1_800_000_000_000).UTC()
	store.now = func() time.Time { return at }
	e := eventlog.Creation("events-http", "user@example.test", "127.0.0.1", false, at)
	stmt, err := e.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "events-http-seed", Statements: []rhiza.SQLStatement{stmt}}); err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "events-reader", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"from":1719784800,"level":"info"}`
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.EventsQuery(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), e.ID) {
		t.Fatalf("key status=%d body=%s", w.Code, w.Body)
	}
	r = httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.EventsQuery(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), e.ID) {
		t.Fatalf("browser status=%d body=%s", w.Code, w.Body)
	}
}

func TestEventsQueryStrictInputAndGuardRevocation(t *testing.T) {
	h, store, _, keys, _ := userCreateHTTPFixture(t)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "events-reader", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.beforeEventRead = func() {
		h.beforeEventRead = nil
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "events-revoke", SQL: `DELETE FROM api_key_access WHERE key_name='events-reader'`}); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(`{"from":1719784800,"level":"info"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.EventsQuery(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoked key status=%d body=%s", w.Code, w.Body)
	}
	_, parserToken, err := keys.Create(context.Background(), nil, apikey.Request{Name: "events-parser", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"from":null,"level":"info"}`, `{"from":1719784800,"level":null}`, `{"from":1719784800,"level":"info","from":1719784800}`, `{"from":1719784800,"level":"info","unknown":1}`, `{"from":9223372036854776,"level":"info"}`, "\xff"} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "API-Key "+parserToken)
		w := httptest.NewRecorder()
		h.EventsQuery(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status=%d", body, w.Code)
		}
	}
	for _, authorization := range []string{"", "Bearer ignored", "API-Key bad"} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(`{"from":1719784800,"level":"info"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		h.EventsQuery(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("auth=%q status=%d", authorization, w.Code)
		}
	}
	r = httptest.NewRequest(http.MethodGet, "/auth/v1/events", nil)
	w = httptest.NewRecorder()
	h.EventsQuery(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d", w.Code)
	}
}

func TestEventsQueryBrowserSnapshotRevocation(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"session", `UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE subject='admin'`},
		{"role", `DELETE FROM rbac_user_roles WHERE subject='admin'`},
		{"expiry", `UPDATE identity_users SET user_expires_at_unix_ms=1 WHERE subject='admin'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, _, _, cookie := userCreateHTTPFixture(t)
			at := time.UnixMilli(1_800_000_000_000).UTC()
			store.now = func() time.Time { return at }
			e := eventlog.Creation("events-browser-revoke", "private@example.test", "192.0.2.1", false, at)
			stmt, err := e.Statement("1=1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "events-browser-seed", Statements: []rhiza.SQLStatement{stmt}}); err != nil {
				t.Fatal(err)
			}
			query := `{"from":1719784800,"level":"info"}`
			req := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(query))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			res := httptest.NewRecorder()
			h.EventsQuery(res, req)
			if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "private@example.test") || !strings.Contains(res.Body.String(), "192.0.2.1") {
				t.Fatalf("initial status=%d body=%s", res.Code, res.Body)
			}
			called := false
			h.beforeEventRead = func() {
				called = true
				h.beforeEventRead = nil
				if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "events-browser-revoke", SQL: tc.sql}); err != nil {
					t.Fatal(err)
				}
			}
			req = httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(query))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			res = httptest.NewRecorder()
			h.EventsQuery(res, req)
			if !called || res.Code != http.StatusForbidden || strings.Contains(res.Body.String(), "private@example.test") || strings.Contains(res.Body.String(), "192.0.2.1") {
				t.Fatalf("revoked status=%d body=%s", res.Code, res.Body)
			}
		})
	}
}

func TestEventsQueryHeadersAndBodyLimit(t *testing.T) {
	h, _, _, keys, _ := userCreateHTTPFixture(t)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "events-header", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, contentType := range []string{"", "text/plain", "application/json, application/json"} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(`{"from":1719784800,"level":"info"}`))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		r.Header.Set("Authorization", "API-Key "+token)
		w := httptest.NewRecorder()
		h.EventsQuery(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("content type=%q status=%d", contentType, w.Code)
		}
	}
	large := `{"from":1719784800,"level":"info"}` + strings.Repeat(" ", 8200)
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(large))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.EventsQuery(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("large body status=%d", w.Code)
	}
}

func TestEventsQueryRejectsCaseAliases(t *testing.T) {
	h, _, _, _, cookie := userCreateHTTPFixture(t)
	for _, body := range []string{
		`{"From":1719784800,"level":"info"}`,
		`{"from":1719784800,"level":"info","Level":"critical"}`,
		`{"from":1719784800,"level":"info","TYP":"NewRauthyAdmin"}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/events", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.EventsQuery(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("case alias status=%d body=%s", w.Code, w.Body)
		}
	}
}

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

func TestSessionsHandlerAPIKeyPaginationHeaders(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.SetUserListThreshold(1); err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "sessions-reader", Access: []apikey.Access{{Group: "Sessions", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"admin", "member"} {
		if _, err := h.browser.CreateSession(context.Background(), subject, "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), ""); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for page := range 3 {
		query := "?page_size=1"
		if cursor != "" {
			query += "&continuation_token=" + url.QueryEscape(cursor)
		}
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/sessions"+query, nil)
		r.Header.Set("Authorization", "API-Key "+token)
		w := httptest.NewRecorder()
		h.Sessions(w, r)
		res := w.Result()
		var payload []Session
		if json.NewDecoder(res.Body).Decode(&payload) != nil || len(payload) != 1 {
			t.Fatalf("page=%d payload=%#v", page, payload)
		}
		if res.StatusCode != http.StatusPartialContent || res.Header.Get("X-Page-Size") != "1" || res.Header.Get("X-Page-Count") == "" || res.Header.Get("X-User-Count") != "" {
			t.Fatalf("page=%d status=%d headers=%v body=%s", page, res.StatusCode, res.Header, w.Body)
		}
		if payload[0].ID != "" {
			seen[payload[0].ID] = true
		}
		cursor = res.Header.Get("X-Continuation-Token")
		if (page < 2) != (cursor != "") {
			t.Fatalf("page=%d token=%q", page, cursor)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("unique sessions=%d", len(seen))
	}
}

func TestSessionsHandlerBrowserAdminAndDeniedUser(t *testing.T) {
	t.Parallel()
	h, _, adminCookie, _ := membershipHTTPFixture(t)
	if err := h.SetUserListThreshold(100); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/sessions", nil)
	r.AddCookie(adminCookie)
	w := httptest.NewRecorder()
	h.Sessions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("admin status=%d body=%s", w.Code, w.Body)
	}
	member, err := h.browser.CreateSession(context.Background(), "member", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	mc, err := browser.SessionCookie(h.issuer, member.Token, member.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	mcsrf, err := browser.DeriveCSRFToken(member.Token)
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/auth/v1/sessions", nil)
	r.AddCookie(mc)
	r.Header.Set("X-CSRF-Token", mcsrf)
	w = httptest.NewRecorder()
	h.Sessions(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("regular-user browser denial status=%d body=%s", w.Code, w.Body)
	}
}

func TestSessionsHandlerDelegatedAdminScopedPaginationAndCount(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	ctx := context.Background()
	insertActive(t, store.db, "grouped")
	insertActive(t, store.db, "outside")
	other, err := store.CreateGroup(ctx, "admin", "other/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "goauthy_admin:team/*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "session-delegated-scope", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('member',?,0)`, Args: []any{role.ID}},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) SELECT subject,id,0 FROM (SELECT 'member' subject UNION ALL SELECT 'grouped') CROSS JOIN rbac_groups WHERE name='team/a'`},
		{SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) VALUES('outside',?,0)`, Args: []any{other.ID}},
	}}); err != nil {
		t.Fatal(err)
	}
	member, err := h.browser.CreateSession(ctx, "member", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	for i, subject := range []string{"grouped", "outside"} {
		if _, err := h.browser.CreateSession(ctx, subject, "pwd", time.Date(2100, 1, 1, 0, i, 0, 0, time.UTC), ""); err != nil {
			t.Fatal(err)
		}
	}
	cookie, err := browser.SessionCookie(h.issuer, member.Token, member.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetUserListThreshold(1); err != nil {
		t.Fatal(err)
	}
	request := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/sessions"+query, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.Sessions(w, r)
		return w
	}
	first := request("?page_size=1")
	if first.Code != http.StatusPartialContent || first.Header().Get("X-Page-Count") != "2" || first.Header().Get("X-Page-Size") != "1" || first.Header().Get("X-Continuation-Token") == "" {
		t.Fatalf("first status=%d headers=%v", first.Code, first.Header())
	}
	seen := map[string]bool{}
	for _, w := range []*httptest.ResponseRecorder{first, request("?page_size=1&continuation_token=" + url.QueryEscape(first.Header().Get("X-Continuation-Token")))} {
		var payload []Session
		if err := json.NewDecoder(w.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		for _, item := range payload {
			if item.UserID != nil {
				seen[*item.UserID] = true
			}
		}
	}
	if len(seen) != 2 || !seen["member"] || !seen["grouped"] || seen["outside"] || seen["admin"] {
		t.Fatalf("delegated sessions=%v", seen)
	}
}

func TestSessionsHandlerWrongAPIKeyRightDenied(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "groups-reader", Access: []apikey.Access{{Group: "Groups", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/sessions", nil)
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.Sessions(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong right status=%d body=%s", w.Code, w.Body)
	}
}

func TestSessionsHandlerAdminRejectsQueryBodyAndCrossSite(t *testing.T) {
	t.Parallel()
	h, _, adminCookie, _ := membershipHTTPFixture(t)
	for _, tc := range []struct {
		name, suffix, body, site string
		want                     int
	}{
		{"query", "?x=1", "", "", http.StatusBadRequest},
		{"body", "", "{}", "", http.StatusBadRequest},
		{"cross-site", "", "", "cross-site", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/v1/sessions"+tc.suffix, strings.NewReader(tc.body))
			r.AddCookie(adminCookie)
			if tc.site != "" {
				r.Header.Set("Sec-Fetch-Site", tc.site)
			}
			w := httptest.NewRecorder()
			h.Sessions(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body)
			}
		})
	}
}

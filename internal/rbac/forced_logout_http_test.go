package rbac

import (
	"context"
	"errors"
	"io"
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

func forceLogoutRequest(target string, cookie *http.Cookie, csrf, auth, query, body string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/auth/v1/sessions/"+target+query, strings.NewReader(body))
	r.SetPathValue("subject", target)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

func TestForceLogoutUserDelegatedScope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, role, group, target string
		want                      int
	}{
		{"exact match", "rauthy_admin:team/a", "team/a", "member", http.StatusOK},
		{"wildcard match", "rauthy_admin:team/*", "team/a", "member", http.StatusOK},
		{"unmanaged group", "rauthy_admin:team/*", "other/x", "member", http.StatusForbidden},
		{"no target group", "rauthy_admin:team/*", "", "member", http.StatusForbidden},
		{"admin target", "rauthy_admin:team/*", "team/a", "admin", http.StatusForbidden},
		{"delegated self", "rauthy_admin:team/*", "team/a", "delegated", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, _, _ := membershipHTTPFixture(t)
			ctx := context.Background()
			insertActive(t, store.db, "delegated")
			role, err := store.CreateRole(ctx, "admin", tc.role, nil)
			if err != nil {
				t.Fatal(err)
			}
			group, err := store.CreateGroup(ctx, "admin", "other/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			teamRows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id FROM rbac_groups WHERE name='team/a'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(teamRows.Rows) != 1 {
				t.Fatalf("team group rows=%#v err=%v", teamRows.Rows, err)
			}
			team := Entity{ID: teamRows.Rows[0][0].(string)}
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "force-http-delegated-seed-" + tc.name, Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('delegated',?,0)`, Args: []any{role.ID}},
			}}); err != nil {
				t.Fatal(err)
			}
			if tc.group != "" {
				gid := team.ID
				if tc.group == "other/x" {
					gid = group.ID
				}
				if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "force-http-target-group-" + tc.name, SQL: `INSERT INTO rbac_user_groups(subject,group_id,granted_at_unix_ms) VALUES(?,?,0)`, Args: []any{tc.target, gid}}); err != nil {
					t.Fatal(err)
				}
			}
			issued, err := h.browser.CreateSession(ctx, "delegated", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
			if err != nil {
				t.Fatal(err)
			}
			if tc.target == "member" {
				if _, err := h.browser.CreateSession(ctx, tc.target, "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), ""); err != nil {
					t.Fatal(err)
				}
			}
			cookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			csrf, err := browser.DeriveCSRFToken(issued.Token)
			if err != nil {
				t.Fatal(err)
			}
			before := countRows(t, store, `SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout'`)
			w := httptest.NewRecorder()
			h.ForceLogoutUser(w, forceLogoutRequest(tc.target, cookie, csrf, "", "", ""))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s want=%d", w.Code, w.Body, tc.want)
			}
			after := countRows(t, store, `SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout'`)
			wantDelta := int64(0)
			if tc.want == http.StatusOK {
				wantDelta = 1
			}
			if after-before != wantDelta {
				t.Fatalf("event delta=%d", after-before)
			}
			if tc.want != http.StatusOK && countRows(t, store, `SELECT COUNT(*) FROM browser_sessions WHERE subject='`+tc.target+`' AND revoked_at_unix_ms IS NULL`) == 0 {
				t.Fatalf("denied target session was revoked")
			}
		})
	}
}

func TestForceLogoutUserBoundariesAndAdmin(t *testing.T) {
	t.Parallel()
	h, store, adminCookie, csrf := membershipHTTPFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name, target, query, body string
		cookie                    *http.Cookie
		csrf                      string
		want                      int
	}{
		{"admin", "member", "", "", adminCookie, csrf, http.StatusOK},
		{"missing target", "missing", "", "", adminCookie, csrf, http.StatusNotFound},
		{"anonymous", "member", "", "", nil, "", http.StatusUnauthorized},
		{"missing csrf", "member", "", "", adminCookie, "", http.StatusUnauthorized},
		{"query", "member", "?x=1", "", adminCookie, csrf, http.StatusBadRequest},
		{"body", "member", "", "{}", adminCookie, csrf, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ForceLogoutUser(w, forceLogoutRequest(tc.target, tc.cookie, tc.csrf, "", tc.query, tc.body))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s want=%d", w.Code, w.Body, tc.want)
			}
		})
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(1) {
		t.Fatalf("event count=%#v err=%v", rows.Rows, err)
	}
}

func TestForceLogoutUserAPIKeyAndNoAmbientFallback(t *testing.T) {
	t.Parallel()
	h, store, adminCookie, csrf := membershipHTTPFixture(t)
	keys, err := apikey.NewStore(store.db)
	if err != nil {
		t.Fatal(err)
	}
	_, limited, err := keys.Create(context.Background(), nil, apikey.Request{Name: "session-read", Access: []apikey.Access{{Group: "Sessions", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	store.BindAPIKeys(keys)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "session-delete", Access: []apikey.Access{{Group: "Sessions", AccessRights: []apikey.Right{apikey.Delete}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, auth string
		cookie     *http.Cookie
		want       int
	}{
		{"api key", "API-Key " + token, nil, http.StatusOK},
		{"wrong right", "API-Key " + limited, adminCookie, http.StatusForbidden},
		{"malformed no fallback", "Bearer malformed", adminCookie, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ForceLogoutUser(w, forceLogoutRequest("member", tc.cookie, csrf, tc.auth, "", ""))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s want=%d", w.Code, w.Body, tc.want)
			}
		})
	}
}

func TestForceLogoutUserReadAndEntropyFailures(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	r := forceLogoutRequest("member", cookie, csrf, "", "", "")
	r.Body = io.NopCloser(iotest.ErrReader(errors.New("body unavailable")))
	w := httptest.NewRecorder()
	h.ForceLogoutUser(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("body read failure status=%d", w.Code)
	}
	store.random = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	w = httptest.NewRecorder()
	h.ForceLogoutUser(w, forceLogoutRequest("member", cookie, csrf, "", "", ""))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("entropy failure status=%d", w.Code)
	}
	if countRows(t, store, `SELECT COUNT(*) FROM event_log WHERE typ='ForcedLogout'`) != 0 || countRows(t, store, `SELECT COUNT(*) FROM oidc_backchannel_deliveries`) != 0 {
		t.Fatal("failed request committed a logout operation")
	}
}

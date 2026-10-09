//go:build confirmationproof

package login

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAuthorizeUnauthenticatedSessionReuseCost(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	initial := httptest.NewRecorder()
	h.Authorize(initial, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if initial.Code != http.StatusOK {
		t.Fatalf("initial authorize status=%d", initial.Code)
	}
	if interactionPattern.FindStringSubmatch(initial.Body.String()) == nil {
		t.Fatal("no-cookie authorize did not render an interaction")
	}
	cookieName, err := browser.CookieName(h.issuer)
	if err != nil {
		t.Fatal("session cookie name unavailable")
	}
	var sessionCookie *http.Cookie
	for _, cookie := range initial.Result().Cookies() {
		if cookie.Name == cookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("initial authorize did not issue a session cookie")
	}
	digest, err := browser.CanonicalTokenDigest(sessionCookie.Value)
	if err != nil {
		t.Fatal("initial session cookie was not canonical")
	}

	wantReads := -1
	if value := os.Getenv("CONFIRMATION_EXPECT_SESSION_READS"); value != "" {
		wantReads, err = strconv.Atoi(value)
		if err != nil || wantReads < 0 {
			t.Fatal("invalid CONFIRMATION_EXPECT_SESSION_READS")
		}
	}
	for index, tc := range []struct {
		name       string
		touchDue   bool
		legacyPeer bool
		wantTouch  int
	}{
		{name: "fresh-peer-bound"},
		{name: "touch-due-peer-bound", touchDue: true, wantTouch: 1},
		{name: "fresh-legacy-empty-peer", legacyPeer: true},
	} {
		if tc.touchDue || tc.legacyPeer {
			sql, args := `UPDATE browser_sessions SET last_seen_at_unix_ms=? WHERE token_digest=?`, []any{nil, digest}
			if tc.touchDue {
				args[0] = time.Now().Add(-11 * time.Second).UnixMilli()
			}
			if tc.legacyPeer {
				sql, args = `UPDATE browser_sessions SET peer_ip='' WHERE token_digest=?`, []any{digest}
			}
			if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("session-cost-setup-%d", index), SQL: sql, Args: args}); err != nil {
				t.Fatalf("scenario %s setup failed", tc.name)
			}
		}

		request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
		request.AddCookie(sessionCookie)
		probe := &browser.SessionCostProbe{}
		request = request.WithContext(browser.WithSessionCostProbe(request.Context(), probe))
		response := httptest.NewRecorder()
		started := time.Now()
		h.Authorize(response, request)
		elapsed := time.Since(started)
		reads, touches := probe.Counts()
		if response.Code != http.StatusOK {
			t.Fatalf("scenario %s status=%d", tc.name, response.Code)
		}
		if reads < 1 || wantReads >= 0 && reads != wantReads {
			t.Fatalf("scenario %s session reads=%d want=%d (set -1 to report only)", tc.name, reads, wantReads)
		}
		if touches != tc.wantTouch {
			t.Fatalf("scenario %s touch submissions=%d want=%d", tc.name, touches, tc.wantTouch)
		}
		var reused bool
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == cookieName && cookie.Value == sessionCookie.Value {
				reused = true
			}
		}
		if !reused || interactionPattern.FindStringSubmatch(response.Body.String()) == nil {
			t.Fatalf("scenario %s did not reuse the session and render an interaction", tc.name)
		}
		t.Logf("scenario=%s session_selects=%d touch_submissions=%d elapsed=%s", tc.name, reads, touches, elapsed)
	}
}

func TestAuthorizeSessionReusePreservesTouchAfterThemeDelay(t *testing.T) {
	h, _ := testHandlerWithDB(t, false)
	now := time.Now().UTC().Truncate(time.Millisecond)
	h.now = func() time.Time { return now }
	browser.SetSessionCostClock(h.browser, func() time.Time { return now })
	delayTheme := false
	h.SetThemeURLResolver(func(context.Context, string) (string, error) {
		if delayTheme {
			now = now.Add(browser.SessionCostTouchInterval() + time.Millisecond)
		}
		return "", nil
	})

	first := httptest.NewRecorder()
	h.Authorize(first, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if first.Code != http.StatusOK || interactionPattern.FindStringSubmatch(first.Body.String()) == nil {
		t.Fatalf("initial authorize status=%d body_has_interaction=%v", first.Code, interactionPattern.FindStringSubmatch(first.Body.String()) != nil)
	}
	cookieName, err := browser.CookieName(h.issuer)
	if err != nil {
		t.Fatal("session cookie name unavailable")
	}
	var sessionCookie *http.Cookie
	for _, cookie := range first.Result().Cookies() {
		if cookie.Name == cookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("initial authorize did not issue a session cookie")
	}

	delayTheme = true
	probe := &browser.SessionCostProbe{}
	request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	request.AddCookie(sessionCookie)
	request = request.WithContext(browser.WithSessionCostProbe(request.Context(), probe))
	response := httptest.NewRecorder()
	h.Authorize(response, request)
	reads, touches := probe.Counts()
	if response.Code != http.StatusOK || interactionPattern.FindStringSubmatch(response.Body.String()) == nil {
		t.Fatalf("delayed authorize status=%d body_has_interaction=%v", response.Code, interactionPattern.FindStringSubmatch(response.Body.String()) != nil)
	}
	var reused bool
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie.Name && cookie.Value == sessionCookie.Value {
			reused = true
		}
	}
	if !reused {
		t.Fatal("delayed authorize did not reuse the original session cookie")
	}
	if reads != 2 || touches != 1 {
		t.Fatalf("touch interval crossed during theme resolution: session reads=%d touch submissions=%d want=2/1", reads, touches)
	}
	t.Logf("scenario=theme-delay-over-touch-interval session_selects=%d touch_submissions=%d", reads, touches)
}

func TestAuthorizeInitSnapshotRechecksFinalInteractionAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		args func(string) []any
	}{
		{name: "revoked", sql: `UPDATE browser_sessions SET revoked_at_unix_ms=? WHERE token_digest=?`, args: func(digest string) []any { return []any{time.Now().UnixMilli(), digest} }},
		{name: "peer changed", sql: `UPDATE browser_sessions SET peer_ip=? WHERE token_digest=?`, args: func(digest string) []any { return []any{"203.0.113.222", digest} }},
		{name: "idle expired", sql: `UPDATE browser_sessions SET last_seen_at_unix_ms=1 WHERE token_digest=?`, args: func(digest string) []any { return []any{digest} }},
		{name: "init authentication changed", sql: `UPDATE browser_sessions SET subject='user-1', auth_method='pwd' WHERE token_digest=?`, args: func(digest string) []any { return []any{digest} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db := testHandlerWithDB(t, false)
			first := httptest.NewRecorder()
			h.Authorize(first, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
			if first.Code != http.StatusOK {
				t.Fatalf("initial authorize status=%d", first.Code)
			}
			cookieName, err := browser.CookieName(h.issuer)
			if err != nil {
				t.Fatal("session cookie name unavailable")
			}
			var cookie *http.Cookie
			for _, candidate := range first.Result().Cookies() {
				if candidate.Name == cookieName {
					cookie = candidate
					break
				}
			}
			if cookie == nil {
				t.Fatal("initial authorize did not set session cookie")
			}
			digest, err := browser.CanonicalTokenDigest(cookie.Value)
			if err != nil {
				t.Fatal("initial session cookie was not canonical")
			}

			probe := &browser.SessionCostProbe{}
			gateRan := false
			var mutationErr error
			probe.BeforeNextInteractionInsert(func() {
				gateRan = true
				_, mutationErr = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "session-final-guard-" + tc.name, SQL: tc.sql, Args: tc.args(digest)})
			})
			request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
			request.AddCookie(cookie)
			request = request.WithContext(browser.WithSessionCostProbe(request.Context(), probe))
			response := httptest.NewRecorder()
			h.Authorize(response, request)
			if !gateRan || mutationErr != nil {
				t.Fatalf("final-insert gate ran=%v mutation err=%v", gateRan, mutationErr)
			}
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Set-Cookie") != "" || interactionPattern.FindStringSubmatch(response.Body.String()) != nil {
				t.Fatalf("changed session authority was accepted: status=%d cookies=%v body_has_interaction=%v", response.Code, response.Result().Cookies(), interactionPattern.FindStringSubmatch(response.Body.String()) != nil)
			}
			result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM browser_authorization_interactions WHERE session_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
				t.Fatalf("rejected final insert did not preserve only the original interaction: rows=%v err=%v", result.Rows, err)
			}
		})
	}
}

func TestAuthorizeSessionLookupFallbackControls(t *testing.T) {
	t.Run("malformed cookie falls back to a fresh session", func(t *testing.T) {
		h := testHandler(t)
		cookieName, err := browser.CookieName(h.issuer)
		if err != nil {
			t.Fatal("session cookie name unavailable")
		}
		request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
		request.AddCookie(&http.Cookie{Name: cookieName, Value: "malformed"})
		response := httptest.NewRecorder()
		h.Authorize(response, request)
		if response.Code != http.StatusOK || interactionPattern.FindStringSubmatch(response.Body.String()) == nil {
			t.Fatalf("malformed-cookie fallback status=%d body_has_interaction=%v", response.Code, interactionPattern.FindStringSubmatch(response.Body.String()) != nil)
		}
		issued := false
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == cookieName && cookie.Value != "malformed" {
				issued = true
			}
		}
		if !issued {
			t.Fatal("malformed cookie did not fall back to a fresh session cookie")
		}
	})

	t.Run("failed first lookup retains retry path", func(t *testing.T) {
		h := testHandler(t)
		first := httptest.NewRecorder()
		h.Authorize(first, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
		if first.Code != http.StatusOK || len(first.Result().Cookies()) == 0 {
			t.Fatalf("initial authorize status=%d cookies=%v", first.Code, first.Result().Cookies())
		}
		cookie := first.Result().Cookies()[0]
		probe := &browser.SessionCostProbe{}
		probe.FailNextSessionRead()
		request := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
		request.AddCookie(cookie)
		request = request.WithContext(browser.WithSessionCostProbe(request.Context(), probe))
		response := httptest.NewRecorder()
		h.Authorize(response, request)
		reads, touches := probe.Counts()
		if response.Code != http.StatusOK || interactionPattern.FindStringSubmatch(response.Body.String()) == nil {
			t.Fatalf("failed-first-read fallback status=%d body_has_interaction=%v", response.Code, interactionPattern.FindStringSubmatch(response.Body.String()) != nil)
		}
		if probe.SessionReadFailures() != 1 || reads != 2 || touches != 0 {
			t.Fatalf("fallback query counts reads=%d injected_failures=%d touches=%d", reads, probe.SessionReadFailures(), touches)
		}
		var reused bool
		for _, candidate := range response.Result().Cookies() {
			if candidate.Name == cookie.Name && candidate.Value == cookie.Value {
				reused = true
			}
		}
		if !reused {
			t.Fatal("successful retry did not reuse the original session cookie")
		}
	})
}

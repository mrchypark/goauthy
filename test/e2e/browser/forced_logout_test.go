package browser

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/rbac"
)

func TestForcedLogoutUserLifecycle(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_FORCED_LOGOUT") != "1" {
		t.Skip("set GOAUTHY_E2E_FORCED_LOGOUT=1 to run forced-logout E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if secondary == "" {
		secondary = primary
	}
	username, password, secret := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD"), os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || username == "" || password == "" || secret == "" {
		t.Fatal("GOAUTHY_E2E_URL, browser username/password, and client secret are required")
	}
	email := os.Getenv("GOAUTHY_E2E_BROWSER_EMAIL")
	nodes := []string{primary}
	if secondary != primary {
		nodes = append(nodes, secondary)
	}
	if tertiary != "" && tertiary != primary && tertiary != secondary {
		nodes = append(nodes, tertiary)
	}
	if len(nodes) != 1 && len(nodes) != 3 {
		t.Fatal("forced logout gate requires one standalone node or exactly three HA nodes")
	}
	userClient := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, userCookie := loginForAuthorizationURL(t, userClient, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "forced-logout-user", "forced-logout-user-nonce"), primary, secondary, username, password, "forced-logout-user")
	tokens := exchangeCode(t, userClient, primary, secret, defaultRedirectURI, code, verifier)
	if tokens.AccessToken == "" {
		t.Fatal("forced-logout user login returned no access token")
	}

	adminClient := newBrowserClient(t)
	_, adminCookie := loginForAuthorizationURL(t, adminClient, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "forced-logout-admin", "forced-logout-admin-nonce"), primary, secondary, username, password, "forced-logout-admin")
	csrf, err := csrfFromCookie(adminCookie)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		assertForcedLogoutSessionListing(t, adminClient, node, userCookie, false)
	}
	deleted := exerciseSingleSessionDeletion(t, primary, secondary, nodes, username, password, secret, adminClient, csrf, userClient, tokens.AccessToken)
	response := do(t, adminClient, http.MethodDelete, primary+"/auth/v1/sessions/bootstrap-admin", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("forced logout status=%d, want %d", response.StatusCode, http.StatusOK)
	}
	for _, node := range nodes {
		assertUserDeleteSessionRejected(t, node, userCookie, "forced-logout-old-session")
		assertForcedLogoutInactive(t, userClient, node, secret, tokens.AccessToken)
	}

	fresh := newBrowserClient(t)
	_, freshCookie := loginForAuthorizationURL(t, fresh, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "forced-logout-fresh", "forced-logout-fresh-nonce"), primary, secondary, username, password, "forced-logout-fresh")
	if freshCookie == nil || freshCookie.Value == userCookie.Value {
		t.Fatal("fresh login did not establish a replacement session")
	}
	want := eventlog.Event{Level: eventlog.Notice, Type: eventlog.ForcedLogout}
	var reference eventlog.Event
	for _, node := range nodes {
		assertForcedLogoutSessionListing(t, fresh, node, userCookie, true)
		event := waitForForcedLogoutEvent(t, fresh, node, email)
		if event.ID == "" || event.Timestamp <= 0 || event.Level != want.Level || event.Type != want.Type || event.IP != nil || event.Data != nil || event.Text == nil || *event.Text != email {
			t.Fatalf("invalid forced logout event node=%s event=%+v", node, event)
		}
		if reference.ID == "" {
			reference = event
		} else if !reflect.DeepEqual(reference, event) {
			t.Fatalf("forced logout POST differs node=%s reference=%+v event=%+v", node, reference, event)
		}
		stream := collectStreamEvents(t, fresh, node, "latest=1000&level=notice", func(events []eventlog.Event) bool { return hasForcedLogoutEvent(events, email) })
		matches := matchingForcedLogoutEvents(stream, email)
		if len(matches) != 1 || !reflect.DeepEqual(matches[0], event) {
			t.Fatalf("forced logout SSE node=%s matches=%+v want=%+v", node, matches, event)
		}
	}
	global, globalFresh := exerciseGlobalSessionLogout(t, primary, secondary, secret, nodes, username, password)
	for _, node := range nodes {
		if count := len(matchingForcedLogoutEvents(queryLifecycleEvents(t, globalFresh, node), email)); count != 1 {
			t.Fatalf("global logout changed ForcedLogout event count node=%s count=%d", node, count)
		}
	}
	if path := os.Getenv("GOAUTHY_E2E_FORCED_LOGOUT_STATE"); path != "" {
		if !filepath.IsAbs(path) {
			t.Fatal("forced logout state path must be absolute")
		}
		data, err := json.Marshal(forcedLogoutState{Event: reference, CookieName: userCookie.Name, CookieValue: userCookie.Value, AccessToken: tokens.AccessToken, DeletedSession: deleted, Global: global})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// This fixture contains test credentials and is kept only in the owning
// script's private temporary directory; never print its contents.
type forcedLogoutState struct {
	Event          eventlog.Event        `json:"event"`
	CookieName     string                `json:"cookie_name"`
	CookieValue    string                `json:"cookie_value"`
	AccessToken    string                `json:"access_token"`
	DeletedSession deletedSessionState   `json:"deleted_session"`
	Global         []deletedSessionState `json:"global"`
}

func TestForcedLogoutUserPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_FORCED_LOGOUT_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_FORCED_LOGOUT_PERSISTENCE=1 after restarting the same deployment")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	if secondary == "" {
		secondary = primary
	}
	username, password, secret := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD"), os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || username == "" || password == "" || secret == "" {
		t.Fatal("GOAUTHY_E2E_URL, browser username/password, and client secret are required")
	}
	path := os.Getenv("GOAUTHY_E2E_FORCED_LOGOUT_STATE")
	if !filepath.IsAbs(path) {
		t.Fatal("forced logout state path must be absolute")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var state forcedLogoutState
	if err := json.NewDecoder(io.LimitReader(f, 32<<10)).Decode(&state); err != nil || state.Event.ID == "" || state.Event.Type != eventlog.ForcedLogout || state.Event.Text == nil || state.CookieName == "" || state.CookieValue == "" || state.AccessToken == "" || len(state.Global) != 2 {
		t.Fatal("invalid forced logout persistence fixture")
	}
	nodes := []string{primary}
	if secondary != primary {
		nodes = append(nodes, secondary)
	}
	if third := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/"); third != "" && third != primary && third != secondary {
		nodes = append(nodes, third)
	}
	if len(nodes) != 1 && len(nodes) != 3 {
		t.Fatal("persistence gate requires one standalone node or exactly three HA nodes")
	}
	cookie := &http.Cookie{Name: state.CookieName, Value: state.CookieValue}
	client := newBrowserClient(t)
	for _, node := range nodes {
		assertUserDeleteSessionRejected(t, node, cookie, "force-logout-persisted-session")
		assertForcedLogoutInactive(t, client, node, secret, state.AccessToken)
	}
	_, _ = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "forced-logout-persisted", "forced-logout-persisted-nonce"), primary, secondary, username, password, "forced-logout-persisted")
	verifyDeletedSession(t, client, nodes, secret, state.DeletedSession)
	verifyGlobalSessionLogout(t, client, nodes, secret, state.Global)
	for _, node := range nodes {
		assertForcedLogoutSessionListing(t, client, node, cookie, true)
		got := waitForForcedLogoutEvent(t, client, node, *state.Event.Text)
		if !reflect.DeepEqual(state.Event, got) {
			t.Fatalf("persisted forced logout event differs node=%s", node)
		}
		stream := collectStreamEvents(t, client, node, "latest=1000&level=notice", func(events []eventlog.Event) bool { return hasForcedLogoutEvent(events, *state.Event.Text) })
		matches := matchingForcedLogoutEvents(stream, *state.Event.Text)
		if len(matches) != 1 || !reflect.DeepEqual(state.Event, matches[0]) {
			t.Fatalf("persisted forced logout SSE differs node=%s", node)
		}
	}
}

func assertForcedLogoutSessionListing(t *testing.T, client *http.Client, base string, cookie *http.Cookie, revoked bool) {
	t.Helper()
	assertSubjectSessionListing(t, client, base, cookie, revoked, "bootstrap-admin")
}

func assertSubjectSessionListing(t *testing.T, client *http.Client, base string, cookie *http.Cookie, revoked bool, subject string) {
	t.Helper()
	id, err := browsersession.CanonicalTokenDigest(cookie.Value)
	if err != nil {
		t.Fatal("invalid fixture session")
	}
	for _, state := range []string{"Auth", "LoggedOut"} {
		query := ""
		if state != "Auth" {
			query = "?session_state=" + state
		}
		response := do(t, client, http.MethodGet, base+"/auth/v1/sessions"+query, nil, nil)
		var items []rbac.Session
		err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&items)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || items == nil {
			t.Fatalf("session listing node=%s state=%s status=%d decode=%v", base, state, response.StatusCode, err)
		}
		found := false
		for i, item := range items {
			if item.State != state || item.ID == cookie.Value || item.Exp <= 0 || item.LastSeen <= 0 {
				t.Fatal("invalid session list state or metadata")
			}
			if i > 0 && (items[i-1].Exp < item.Exp || items[i-1].Exp == item.Exp && items[i-1].ID < item.ID) {
				t.Fatal("session list is not expiry/ID descending")
			}
			if item.ID == id {
				found = true
				if item.UserID == nil || *item.UserID != subject || item.IsMFA {
					t.Fatal("unexpected password session metadata")
				}
			}
		}
		if found != (revoked == (state == "LoggedOut")) {
			t.Fatalf("session state membership node=%s state=%s found=%v revoked=%v", base, state, found, revoked)
		}
	}
}

func csrfFromCookie(cookie *http.Cookie) (string, error) {
	if cookie == nil {
		return "", io.ErrUnexpectedEOF
	}
	return browsersession.DeriveCSRFToken(cookie.Value)
}

func assertForcedLogoutInactive(t *testing.T, client *http.Client, base, secret, token string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active bool `json:"active"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload) != nil || payload.Active {
		t.Fatalf("forced logout introspection node=%s status=%d active=%v", base, response.StatusCode, payload.Active)
	}
}

func waitForForcedLogoutEvent(t *testing.T, client *http.Client, base, email string) eventlog.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		matches := matchingForcedLogoutEvents(queryLifecycleEvents(t, client, base), email)
		if len(matches) > 1 {
			t.Fatalf("forced logout event count node=%s count=%d", base, len(matches))
		}
		if len(matches) == 1 {
			return matches[0]
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for forced logout event node=%s", base)
		case <-ticker.C:
		}
	}
}

func matchingForcedLogoutEvents(events []eventlog.Event, email string) []eventlog.Event {
	matches := make([]eventlog.Event, 0, 1)
	for _, event := range events {
		if event.Type == eventlog.ForcedLogout && event.Text != nil && *event.Text == email {
			matches = append(matches, event)
		}
	}
	return matches
}

func hasForcedLogoutEvent(events []eventlog.Event, email string) bool {
	return len(matchingForcedLogoutEvents(events, email)) > 0
}

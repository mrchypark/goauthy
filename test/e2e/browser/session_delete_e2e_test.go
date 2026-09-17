package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/rbac"
)

// Private test credentials, serialized only into the owning script's 0600
// temporary fixture alongside the forced-logout state. Never log these values.
type deletedSessionState struct {
	SID          string `json:"sid"`
	CookieName   string `json:"cookie_name"`
	CookieValue  string `json:"cookie_value"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func exerciseSingleSessionDeletion(t *testing.T, primary, secondary string, nodes []string, username, password, secret string, admin *http.Client, csrf string, keeper *http.Client, keeperToken string) deletedSessionState {
	t.Helper()
	victim := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, cookie := loginForAuthorizationURL(t, victim, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "single-session", "single-session-nonce"), primary, secondary, username, password, "single-session")
	tokens := exchangeCode(t, victim, primary, secret, defaultRedirectURI, code, verifier)
	sid, err := browsersession.CanonicalTokenDigest(cookie.Value)
	if err != nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("missing single-session fixture credentials")
	}
	for _, node := range nodes {
		assertForcedLogoutSessionListing(t, admin, node, cookie, false)
		assertUserInfoSubject(t, victim, node, http.MethodGet, tokens.AccessToken, "bootstrap-admin")
	}
	response := do(t, admin, http.MethodDelete, primary+"/auth/v1/sessions/id/"+sid, nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("single-session delete status=%d", response.StatusCode)
	}
	state := deletedSessionState{SID: sid, CookieName: cookie.Name, CookieValue: cookie.Value, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken}
	verifyDeletedSession(t, admin, nodes, secret, state)
	for _, node := range nodes {
		// Same subject, independent browser session and access token remain usable.
		assertUserInfoSubject(t, keeper, node, http.MethodGet, keeperToken, "bootstrap-admin")
		for _, event := range queryLifecycleEvents(t, admin, node) {
			if event.Type == eventlog.ForcedLogout {
				t.Fatal("single-session deletion emitted user-wide ForcedLogout")
			}
		}
	}
	response = do(t, admin, http.MethodDelete, primary+"/auth/v1/sessions/id/"+sid, nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("repeated single-session delete status=%d", response.StatusCode)
	}
	t.Log("single-session deletion: target rejected, same-user token retained, no ForcedLogout event")
	return state
}

func verifyDeletedSession(t *testing.T, admin *http.Client, nodes []string, secret string, state deletedSessionState) {
	t.Helper()
	sid, err := browsersession.CanonicalTokenDigest(state.CookieValue)
	if err != nil || sid != state.SID || state.CookieName == "" || state.AccessToken == "" || state.RefreshToken == "" {
		t.Fatal("invalid deleted-session persistence fixture")
	}
	cookie := &http.Cookie{Name: state.CookieName, Value: state.CookieValue}
	for _, node := range nodes {
		assertUserDeleteSessionRejected(t, node, cookie, "deleted-session-cookie")
		assertForcedLogoutInactive(t, admin, node, secret, state.AccessToken)
		assertRefreshRejected(t, admin, node, secret, state.RefreshToken)
		for _, filter := range []string{"Auth", "LoggedOut", "Init", "Unknown"} {
			response := do(t, admin, http.MethodGet, node+"/auth/v1/sessions?session_state="+filter, nil, nil)
			var items []rbac.Session
			err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&items)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || items == nil {
				t.Fatalf("deleted-session list node=%s status=%d decode=%v", node, response.StatusCode, err)
			}
			for _, item := range items {
				if item.ID == state.SID {
					t.Fatal("deleted session still listed")
				}
			}
		}
	}
	t.Log("deleted-session cookie/access/refresh rejected and row absent on every node")
}

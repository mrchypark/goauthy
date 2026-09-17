package browser

import (
	"io"
	"net/http"
	"testing"
)

// exerciseGlobalSessionLogout creates two independent live sessions, then
// revokes every browser session through the direct-admin DELETE endpoint.
func exerciseGlobalSessionLogout(t *testing.T, primary, secondary, secret string, nodes []string, username, password string) ([]deletedSessionState, *http.Client) {
	t.Helper()
	admin := newBrowserClient(t)
	_, adminCookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "logout-all-admin", "logout-all-admin-nonce"), primary, secondary, username, password, "logout-all-admin")
	csrf, err := csrfFromCookie(adminCookie)
	if err != nil {
		t.Fatal(err)
	}
	states := make([]deletedSessionState, 0, 2)
	for i, label := range []string{"logout-all-one", "logout-all-two"} {
		client := newBrowserClient(t)
		verifier := pkceVerifier(t)
		code, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), label, label+"-nonce"), primary, secondary, username, password, label)
		tokens := exchangeCode(t, client, primary, secret, defaultRedirectURI, code, verifier)
		if cookie == nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
			t.Fatalf("global session %d login returned incomplete credentials", i+1)
		}
		state := deletedSessionState{CookieName: cookie.Name, CookieValue: cookie.Value, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken}
		// Rotate once on every configured node to prove the refresh grant is live there.
		for _, node := range nodes {
			rotated := refresh(t, client, node, secret, state.RefreshToken)
			if rotated.AccessToken == "" || rotated.RefreshToken == "" {
				t.Fatalf("global session %d refresh on %s returned incomplete credentials", i+1, node)
			}
			state.AccessToken, state.RefreshToken = rotated.AccessToken, rotated.RefreshToken
		}
		for _, node := range nodes {
			assertUserInfoSubject(t, client, node, http.MethodGet, state.AccessToken, "bootstrap-admin")
			assertForcedLogoutSessionListing(t, admin, node, cookie, false)
		}
		states = append(states, state)
	}

	response := do(t, admin, http.MethodDelete, primary+"/auth/v1/sessions", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || len(body) != 0 {
		t.Fatalf("global logout status=%d, want %d", response.StatusCode, http.StatusOK)
	}
	fresh := newBrowserClient(t)
	_, freshCookie := loginForAuthorizationURL(t, fresh, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "logout-all-fresh", "logout-all-fresh-nonce"), primary, secondary, username, password, "logout-all-fresh")
	if freshCookie == nil {
		t.Fatal("fresh login after global logout did not establish a session")
	}
	verifyGlobalSessionLogout(t, fresh, nodes, secret, states)
	for _, node := range nodes {
		assertUserDeleteSessionRejected(t, node, adminCookie, "logout-all-caller-session")
	}
	return states, fresh
}

func verifyGlobalSessionLogout(t *testing.T, client *http.Client, nodes []string, secret string, states []deletedSessionState) {
	t.Helper()
	if len(states) != 2 {
		t.Fatalf("global logout fixture has %d sessions, want 2", len(states))
	}
	for _, state := range states {
		if state.CookieName == "" || state.CookieValue == "" || state.AccessToken == "" || state.RefreshToken == "" {
			t.Fatal("invalid global logout session fixture")
		}
		cookie := &http.Cookie{Name: state.CookieName, Value: state.CookieValue}
		for _, node := range nodes {
			assertUserDeleteSessionRejected(t, node, cookie, "logout-all-old-session")
			assertForcedLogoutInactive(t, client, node, secret, state.AccessToken)
			assertRefreshRejected(t, client, node, secret, state.RefreshToken)
			assertForcedLogoutSessionListing(t, client, node, cookie, true)
		}
	}
}

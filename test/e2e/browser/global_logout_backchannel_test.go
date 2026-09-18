package browser

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestGlobalLogoutBackchannel(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_GLOBAL_LOGOUT_BACKCHANNEL") != "1" {
		t.Skip("set GOAUTHY_E2E_GLOBAL_LOGOUT_BACKCHANNEL=1 to run global logout back-channel E2E")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL"), "/")
	if sinkURL == "" {
		t.Fatal("GOAUTHY_E2E_BACKCHANNEL_SINK_URL is required")
	}
	nodes := []string{primary}
	if secondary != primary {
		nodes = append(nodes, secondary)
	}
	if tertiary != "" && tertiary != primary && tertiary != secondary {
		nodes = append(nodes, tertiary)
	}
	if len(nodes) != 1 && len(nodes) != 3 {
		t.Fatal("global logout back-channel gate requires one standalone node or exactly three HA nodes")
	}

	observer := newBrowserClient(t)
	keys := publicJWKS(t, observer, primary)
	setBackchannelSinkControl(t, sinkURL, 0, 0, http.StatusNoContent)
	baseline := sinkEventCount(t, sinkURL)
	phase := os.Getenv("GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE")
	statePath := os.Getenv("GOAUTHY_E2E_GLOBAL_LOGOUT_STATE")
	if phase != "" && phase != "prepare" && phase != "after-restart" {
		t.Fatalf("GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE=%q must be prepare or after-restart", phase)
	}
	if phase != "" && statePath == "" {
		t.Fatal("GOAUTHY_E2E_GLOBAL_LOGOUT_STATE is required for phased global logout E2E")
	}
	if phase != "" && !filepath.IsAbs(statePath) {
		t.Fatal("GOAUTHY_E2E_GLOBAL_LOGOUT_STATE must be absolute")
	}

	states := make([]deletedSessionState, 0, 2)
	if phase == "after-restart" {
		file, err := os.Open(statePath)
		if err != nil {
			t.Fatal("open global logout fixture")
		}
		data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		file.Close()
		if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &states) != nil || len(states) != 2 {
			t.Fatalf("read global logout state: %v", err)
		}
		for _, state := range states {
			for _, node := range nodes {
				assertUserInfoSubject(t, observer, node, http.MethodGet, state.AccessToken, "bootstrap-admin")
			}
		}
	} else {
		for i, label := range []string{"global-backchannel-one", "global-backchannel-two"} {
			client := newBrowserClient(t)
			verifier := pkceVerifier(t)
			code, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), label, label+"-nonce"), primary, secondary, username, password, label)
			tokens := exchangeCode(t, client, primary, clientSecret, defaultRedirectURI, code, verifier)
			if cookie == nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
				t.Fatalf("session %d login returned incomplete credentials", i+1)
			}
			for _, node := range nodes {
				assertUserInfoSubject(t, client, node, http.MethodGet, tokens.AccessToken, "bootstrap-admin")
			}
			states = append(states, deletedSessionState{CookieName: cookie.Name, CookieValue: cookie.Value, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken})
		}
	}
	if phase == "prepare" {
		data, err := json.Marshal(states)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, data, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}

	admin := newBrowserClient(t)
	_, adminCookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "global-backchannel-admin", "global-backchannel-admin-nonce"), primary, secondary, username, password, "global-backchannel-admin")
	csrf, err := csrfFromCookie(adminCookie)
	if err != nil {
		t.Fatal(err)
	}
	deleteAllSessions(t, admin, primary, csrf)
	event := waitForGlobalLogoutToken(t, sinkURL, baseline)
	firstClaims := assertSubjectOnlyLogoutToken(t, event.Token, keys, primary)
	if event.Status != http.StatusNoContent {
		t.Fatalf("global logout sink status=%d, want %d", event.Status, http.StatusNoContent)
	}

	fresh := newBrowserClient(t)
	freshVerifier := pkceVerifier(t)
	freshCode, freshCookie := loginForAuthorizationURL(t, fresh, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(freshVerifier), "global-backchannel-fresh", "global-backchannel-fresh-nonce"), primary, secondary, username, password, "global-backchannel-fresh")
	freshTokens := exchangeCode(t, fresh, primary, clientSecret, defaultRedirectURI, freshCode, freshVerifier)
	if freshCookie == nil || freshTokens.AccessToken == "" || freshTokens.RefreshToken == "" {
		t.Fatal("fresh login after global logout did not establish a session")
	}
	verifyGlobalSessionLogout(t, fresh, nodes, clientSecret, states)
	for _, node := range nodes {
		assertUserInfoSubject(t, fresh, node, http.MethodGet, freshTokens.AccessToken, "bootstrap-admin")
	}
	freshAdmin := newBrowserClient(t)
	_, freshAdminCookie := loginForAuthorizationURL(t, freshAdmin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "global-backchannel-admin-two", "global-backchannel-admin-two-nonce"), primary, secondary, username, password, "global-backchannel-admin-two")
	freshCSRF, err := csrfFromCookie(freshAdminCookie)
	if err != nil {
		t.Fatal(err)
	}
	secondBaseline := sinkEventCount(t, sinkURL)
	if secondBaseline != baseline+1 {
		t.Fatalf("global logout observed %d deliveries for two sessions of one user/client, want 1", secondBaseline-baseline)
	}
	deleteAllSessions(t, freshAdmin, primary, freshCSRF)
	second := waitForGlobalLogoutToken(t, sinkURL, secondBaseline)
	if second.Token == event.Token {
		t.Fatal("repeated global logout reused the logout token")
	}
	secondClaims := assertSubjectOnlyLogoutToken(t, second.Token, keys, primary)
	if secondClaims.JTI == firstClaims.JTI {
		t.Fatal("separate global logouts reused JTI")
	}
	if second.Status != http.StatusNoContent {
		t.Fatalf("repeated global logout sink status=%d, want %d", second.Status, http.StatusNoContent)
	}
	for _, node := range nodes {
		assertUserDeleteSessionRejected(t, node, freshCookie, "global-backchannel-fresh-revoked")
		assertForcedLogoutInactive(t, fresh, node, clientSecret, freshTokens.AccessToken)
		assertRefreshRejected(t, fresh, node, clientSecret, freshTokens.RefreshToken)
	}
}

func deleteAllSessions(t *testing.T, client *http.Client, base, csrf string) {
	t.Helper()
	response := do(t, client, http.MethodDelete, base+"/auth/v1/sessions", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("global logout status=%d, want empty %d: %v", response.StatusCode, http.StatusOK, err)
	}
}

func sinkEventCount(t *testing.T, sinkURL string) int {
	t.Helper()
	events, err := backchannelEvents(backchannelHTTPClient(t, sinkURL), sinkURL)
	if err != nil {
		t.Fatal(err)
	}
	return len(events)
}

func waitForGlobalLogoutToken(t *testing.T, sinkURL string, baseline int) backchannelEvent {
	t.Helper()
	events := waitForBackchannelEvents(t, sinkURL, func(events []backchannelEvent) bool {
		if len(events) <= baseline {
			return false
		}
		for _, event := range events[baseline:] {
			if event.Status == http.StatusNoContent && event.Token != "" {
				return true
			}
		}
		return false
	})
	for _, event := range events[baseline:] {
		if event.Status == http.StatusNoContent && event.Token != "" {
			return event
		}
	}
	t.Fatalf("global logout delivery disappeared after polling")
	return backchannelEvent{}
}

func assertSubjectOnlyLogoutToken(t *testing.T, compact string, keys jose.JSONWebKeySet, issuer string) oidc.LogoutTokenClaims {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatal("logout token is not compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["sid"]; ok {
		t.Fatal("subject-only logout token contains sid")
	}
	if _, ok := raw["nonce"]; ok {
		t.Fatal("logout token contains nonce")
	}
	var subject string
	if err := json.Unmarshal(raw["sub"], &subject); err != nil || subject != "bootstrap-admin" {
		t.Fatalf("logout token subject=%q", subject)
	}
	claims, err := oidc.VerifyLogoutToken(compact, keys, issuer, "goauthy-dev", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "bootstrap-admin" || claims.SessionID != "" || claims.JTI == "" {
		t.Fatalf("unexpected subject-only logout claims: %#v", claims)
	}
	return claims
}

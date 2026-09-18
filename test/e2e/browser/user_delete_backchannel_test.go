package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestUserDeleteBackchannel(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_USER_DELETE_BACKCHANNEL") != "1" {
		t.Skip("set GOAUTHY_E2E_USER_DELETE_BACKCHANNEL=1")
	}
	primary, secondary, username, password, secret := browserE2EConfig(t)
	nodes := []string{primary}
	if secondary != primary {
		nodes = append(nodes, secondary)
	}
	if third := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/"); third != "" && third != primary && third != secondary {
		nodes = append(nodes, third)
	}
	if len(nodes) != 1 && len(nodes) != 3 {
		t.Fatal("requires standalone or exactly three HA nodes")
	}
	smtpURL, sinkURL := os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL")
	phase, path := os.Getenv("GOAUTHY_E2E_USER_DELETE_BACKCHANNEL_PHASE"), os.Getenv("GOAUTHY_E2E_USER_DELETE_BACKCHANNEL_STATE")
	if smtpURL == "" || sinkURL == "" || !filepath.IsAbs(path) {
		t.Fatal("SMTP, RP sink and absolute private fixture path required")
	}
	if phase != "prepare" && phase != "after-restart" && phase != "after-delete-restart" {
		t.Fatal("invalid user-delete backchannel phase")
	}
	state := forceLogoutBackchannelState{}
	if phase == "prepare" {
		setBackchannelSinkControl(t, sinkURL, 0, 0, http.StatusNoContent)
		state.Email, state.Subject, state.Password = registerSelfAttributeMember(t, primary, secondary, smtpURL)
		for _, label := range []string{"delete-subject-one", "delete-subject-two"} {
			state.Member = append(state.Member, userDeleteBackchannelLogin(t, primary, secondary, state.Email, state.Password, secret, label))
		}
		state.Admin = userDeleteBackchannelLogin(t, primary, secondary, username, password, secret, "delete-subject-admin")
		observer := newBrowserClient(t)
		for _, node := range nodes {
			for _, member := range state.Member {
				assertUserInfoSubject(t, observer, node, http.MethodGet, member.AccessToken, state.Subject)
			}
			assertUserInfoSubject(t, observer, node, http.MethodGet, state.Admin.AccessToken, "bootstrap-admin")
		}
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open user-delete fixture")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	file.Close()
	if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &state) != nil || len(state.Member) != 2 || state.Subject == "" || state.Subject == "bootstrap-admin" || state.Email == "" || state.Password == "" {
		t.Fatal("invalid user-delete fixture")
	}
	for _, session := range append([]deletedSessionState{state.Admin}, state.Member...) {
		if session.CookieName == "" || session.CookieValue == "" || session.AccessToken == "" || session.RefreshToken == "" {
			t.Fatal("incomplete user-delete session fixture")
		}
	}
	adminCookie := &http.Cookie{Name: state.Admin.CookieName, Value: state.Admin.CookieValue}
	admin := clientWithCookie(t, primary, adminCookie)
	if phase == "after-restart" {
		for _, node := range nodes {
			for _, member := range state.Member {
				assertUserInfoSubject(t, admin, node, http.MethodGet, member.AccessToken, state.Subject)
			}
			assertUserInfoSubject(t, admin, node, http.MethodGet, state.Admin.AccessToken, "bootstrap-admin")
		}
		csrf, err := csrfFromCookie(adminCookie)
		if err != nil {
			t.Fatal(err)
		}
		response := do(t, admin, http.MethodDelete, secondary+"/auth/v1/users/"+url.PathEscape(state.Subject), nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusNoContent || len(body) != 0 {
			t.Fatalf("delete status=%d expected empty 204", response.StatusCode)
		}
		event := waitForGlobalLogoutToken(t, sinkURL, 0)
		assertGenericSubjectOnlyToken(t, event.Token, publicJWKS(t, admin, primary), primary, state.Subject)
	}
	for _, member := range state.Member {
		verifyDeletedSession(t, admin, nodes, secret, member)
	}
	for _, node := range nodes {
		assertUserInfoSubject(t, admin, node, http.MethodGet, state.Admin.AccessToken, "bootstrap-admin")
		assertForcedLogoutSessionListing(t, admin, node, adminCookie, false)
		// Two phases over three nodes share the server-observed peer IP. The
		// fifth/sixth failed login deliberately waits 15/18 seconds; successful
		// login does not clear that counter. Bound the request, not the policy.
		negativeClient := newBrowserClient(t)
		negativeClient.Timeout = time.Minute
		assertPasswordLoginWithClient(t, negativeClient, node, node, state.Email, "deleted-subject-password", state.Password, http.StatusUnauthorized)
	}
	if got := sinkEventCount(t, sinkURL); got != 1 {
		t.Fatalf("expected one subject-only delivery for two deleted sessions, got %d", got)
	}
	if phase == "after-delete-restart" {
		tokens := refresh(t, admin, primary, secret, state.Admin.RefreshToken)
		for _, node := range nodes {
			assertUserInfoSubject(t, admin, node, http.MethodGet, tokens.AccessToken, "bootstrap-admin")
		}
	}
}

func userDeleteBackchannelLogin(t *testing.T, primary, secondary, username, password, secret, label string) deletedSessionState {
	t.Helper()
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), label, label+"-nonce"), primary, secondary, username, password, label)
	tokens := exchangeCode(t, client, primary, secret, defaultRedirectURI, code, verifier)
	if cookie == nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("incomplete user-delete login")
	}
	sid, err := browsersession.CanonicalTokenDigest(cookie.Value)
	if err != nil {
		t.Fatal("invalid session cookie")
	}
	return deletedSessionState{SID: sid, CookieName: cookie.Name, CookieValue: cookie.Value, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken}
}

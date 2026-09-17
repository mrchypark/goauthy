package browser

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

type forceLogoutBackchannelState struct {
	Email    string                `json:"email"`
	Subject  string                `json:"subject"`
	Password string                `json:"password"`
	Member   []deletedSessionState `json:"member"`
	Admin    deletedSessionState   `json:"admin"`
}

func TestForceLogoutBackchannel(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL") != "1" {
		t.Skip("set GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL=1 to run force-logout back-channel E2E")
	}
	primary, secondary, adminUser, adminPassword, clientSecret := browserE2EConfig(t)
	smtpURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	backchannelURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL"), "/")
	if smtpURL == "" || backchannelURL == "" {
		t.Fatal("GOAUTHY_E2E_SMTP_SINK_URL is required")
	}
	nodes := []string{primary}
	if secondary != primary {
		nodes = append(nodes, secondary)
	}
	if tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/"); tertiary != "" && tertiary != primary && tertiary != secondary {
		nodes = append(nodes, tertiary)
	}
	if len(nodes) != 1 && len(nodes) != 3 {
		t.Fatal("force logout back-channel requires one standalone node or exactly three HA nodes")
	}
	phase, statePath := os.Getenv("GOAUTHY_E2E_FORCE_LOGOUT_PHASE"), os.Getenv("GOAUTHY_E2E_FORCE_LOGOUT_STATE")
	if phase != "" && phase != "prepare" && phase != "after-restart" {
		t.Fatalf("invalid force logout phase %q", phase)
	}
	if phase != "" && (!filepath.IsAbs(statePath) || statePath == "") {
		t.Fatal("GOAUTHY_E2E_FORCE_LOGOUT_STATE must be absolute")
	}
	setBackchannelSinkControl(t, backchannelURL, 0, 0, http.StatusNoContent)

	mail := newBrowserClient(t)
	state := forceLogoutBackchannelState{}
	if phase == "after-restart" {
		file, err := os.Open(statePath)
		if err != nil {
			t.Fatalf("open force logout state: %v", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		file.Close()
		if readErr != nil || len(data) > 64<<10 || json.Unmarshal(data, &state) != nil || state.Subject == "" || state.Email == "" || state.Password == "" || state.Subject == "bootstrap-admin" || len(state.Member) != 2 || state.Admin.CookieValue == "" || state.Admin.AccessToken == "" || state.Admin.RefreshToken == "" {
			t.Fatalf("read force logout state: %v", err)
		}
	} else {
		state.Email, state.Subject, state.Password = registerSelfAttributeMember(t, primary, secondary, smtpURL)
		for i, label := range []string{"force-backchannel-one", "force-backchannel-two"} {
			client := newBrowserClient(t)
			verifier := pkceVerifier(t)
			code, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), label, label+"-nonce"), primary, secondary, state.Email, state.Password, label)
			tokens := exchangeCode(t, client, primary, clientSecret, defaultRedirectURI, code, verifier)
			if cookie == nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
				t.Fatalf("member session %d incomplete", i+1)
			}
			for _, node := range nodes {
				assertUserInfoSubject(t, client, node, http.MethodGet, tokens.AccessToken, state.Subject)
			}
			state.Member = append(state.Member, deletedSessionState{CookieName: cookie.Name, CookieValue: cookie.Value, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken})
		}
		admin := newBrowserClient(t)
		verifier := pkceVerifier(t)
		code, cookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "force-backchannel-admin", "force-backchannel-admin-nonce"), primary, secondary, adminUser, adminPassword, "force-backchannel-admin")
		tokens := exchangeCode(t, admin, primary, clientSecret, defaultRedirectURI, code, verifier)
		if cookie == nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
			t.Fatal("admin session incomplete")
		}
		state.Admin = deletedSessionState{CookieName: cookie.Name, CookieValue: cookie.Value, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken}
		for _, node := range nodes {
			assertUserInfoSubject(t, admin, node, http.MethodGet, tokens.AccessToken, "bootstrap-admin")
		}
	}
	if phase == "prepare" {
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, data, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if state.Email == "" || state.Subject == "" || state.Password == "" || state.Subject == "bootstrap-admin" || len(state.Member) != 2 || state.Admin.CookieName == "" || state.Admin.CookieValue == "" || state.Admin.AccessToken == "" || state.Admin.RefreshToken == "" {
		t.Fatal("invalid force logout fixture")
	}
	for _, old := range state.Member {
		if old.CookieName == "" || old.CookieValue == "" || old.AccessToken == "" || old.RefreshToken == "" {
			t.Fatal("invalid member session fixture")
		}
		for _, node := range nodes {
			assertUserInfoSubject(t, mail, node, http.MethodGet, old.AccessToken, state.Subject)
		}
	}
	for _, node := range nodes {
		assertUserInfoSubject(t, mail, node, http.MethodGet, state.Admin.AccessToken, "bootstrap-admin")
	}

	admin := newBrowserClient(t)
	_, adminCookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "force-backchannel-delete-admin", "force-backchannel-delete-admin-nonce"), primary, secondary, adminUser, adminPassword, "force-backchannel-delete-admin")
	if adminCookie == nil {
		t.Fatal("force-logout administrator login returned no session cookie")
	}
	csrf, err := csrfFromCookie(adminCookie)
	if err != nil {
		t.Fatal(err)
	}
	baseline := sinkEventCount(t, backchannelURL)
	response := do(t, admin, http.MethodDelete, primary+"/auth/v1/sessions/"+url.PathEscape(state.Subject), nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("force logout status=%d: %v", response.StatusCode, readErr)
	}
	event := waitForGlobalLogoutToken(t, backchannelURL, baseline)
	assertGenericSubjectOnlyToken(t, event.Token, publicJWKS(t, mail, primary), primary, state.Subject)
	if event.Status != http.StatusNoContent {
		t.Fatalf("sink status=%d, want %d", event.Status, http.StatusNoContent)
	}
	if got := sinkEventCount(t, backchannelURL); got != baseline+1 {
		t.Fatalf("force logout sink events=%d, want %d", got, baseline+1)
	}
	for _, old := range state.Member {
		cookie := &http.Cookie{Name: old.CookieName, Value: old.CookieValue}
		for _, node := range nodes {
			assertUserDeleteSessionRejected(t, node, cookie, "force-backchannel-old")
			assertForcedLogoutInactive(t, admin, node, clientSecret, old.AccessToken)
			assertRefreshRejected(t, admin, node, clientSecret, old.RefreshToken)
			assertSubjectSessionListing(t, admin, node, cookie, true, state.Subject)
		}
	}
	adminObserver := clientWithCookie(t, primary, &http.Cookie{Name: state.Admin.CookieName, Value: state.Admin.CookieValue})
	for _, node := range nodes {
		assertUserInfoSubject(t, adminObserver, node, http.MethodGet, state.Admin.AccessToken, "bootstrap-admin")
	}
	rotatedAdmin := refresh(t, adminObserver, primary, clientSecret, state.Admin.RefreshToken)
	if rotatedAdmin.AccessToken == "" || rotatedAdmin.RefreshToken == "" {
		t.Fatal("saved admin refresh failed")
	}
	for _, node := range nodes {
		assertUserInfoSubject(t, adminObserver, node, http.MethodGet, rotatedAdmin.AccessToken, "bootstrap-admin")
		assertForcedLogoutSessionListing(t, adminObserver, node, &http.Cookie{Name: state.Admin.CookieName, Value: state.Admin.CookieValue}, false)
		authorizeWithCookie(t, adminObserver, node, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "force-backchannel-admin-observer", "force-backchannel-admin-observer-nonce")
	}
	member := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, cookie := loginForAuthorizationURL(t, member, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "force-backchannel-fresh", "force-backchannel-fresh-nonce"), primary, secondary, state.Email, state.Password, "force-backchannel-fresh")
	freshTokens := exchangeCode(t, member, primary, clientSecret, defaultRedirectURI, code, verifier)
	if cookie == nil || freshTokens.AccessToken == "" || freshTokens.RefreshToken == "" {
		t.Fatal("fresh member login failed")
	}
	for _, node := range nodes {
		assertUserInfoSubject(t, member, node, http.MethodGet, freshTokens.AccessToken, state.Subject)
	}
	if got := sinkEventCount(t, backchannelURL); got != baseline+1 {
		t.Fatalf("force logout deliveries after revocation checks=%d, want %d", got-baseline, 1)
	}
}

func assertGenericSubjectOnlyToken(t *testing.T, compact string, keys jose.JSONWebKeySet, issuer, subject string) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatal("logout token is not compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(payload, &raw) != nil {
		t.Fatal("invalid logout payload")
	}
	if _, ok := raw["sid"]; ok {
		t.Fatal("subject-only token contains sid")
	}
	if _, ok := raw["nonce"]; ok {
		t.Fatal("logout token contains nonce")
	}
	var got string
	if json.Unmarshal(raw["sub"], &got) != nil || got != subject {
		t.Fatalf("logout subject=%q want=%q", got, subject)
	}
	claims, err := oidc.VerifyLogoutToken(compact, keys, issuer, "goauthy-dev", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != subject || claims.SessionID != "" || claims.JTI == "" {
		t.Fatalf("unexpected subject-only logout claims: %#v", claims)
	}
}

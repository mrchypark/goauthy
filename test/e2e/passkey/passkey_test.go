// Package passkey exercises the deployed passkey boundary with Chrome's CDP
// virtual authenticator. It is deliberately opt-in: a normal unit test run
// must not launch a browser or require a kind cluster.
package passkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	passkeyProfileEnv = "GOAUTHY_E2E_PASSKEY"
	passkeyCaseEnv    = "GOAUTHY_E2E_PASSKEY_CASE"
	forcedMFACase     = "forced-mfa"
	defaultRedirect   = "http://localhost:5555/callback"
	dynamicVerifier   = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
)

var loginInteraction = regexp.MustCompile(`name="interaction" value="([A-Za-z0-9_-]{43})"`)

func TestPasskeyVirtualAuthenticatorAcrossPods(t *testing.T) {
	if os.Getenv(passkeyProfileEnv) != "1" {
		t.Skip("set GOAUTHY_E2E_PASSKEY=1 to run Chrome virtual-authenticator E2E")
	}
	primary := requiredURL(t, "GOAUTHY_E2E_URL")
	secondary := requiredURL(t, "GOAUTHY_E2E_SECONDARY_URL")
	tertiary := requiredURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	if u, err := url.Parse(primary); err != nil || u.Scheme != "http" || u.Hostname() != "localhost" {
		t.Fatalf("passkey E2E requires a stable localhost HTTP origin, got %q", primary)
	}
	username := requiredEnv(t, "GOAUTHY_E2E_BROWSER_USERNAME")
	password := requiredEnv(t, "GOAUTHY_E2E_BROWSER_PASSWORD")
	subject := requiredEnv(t, "GOAUTHY_E2E_BROWSER_SUBJECT")

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	auth := newVirtualAuthenticator(t, ctx)
	defer auth.close()
	browserCtx := auth.ctx

	client := browserClient(t)
	loginPassword(t, client, primary, username, password, "passkey-register")
	csrf := accountCSRF(t, client, primary)
	modification := issueModification(t, client, primary, subject, csrf, password)
	registration := beginRegistration(t, client, primary, subject, csrf, modification)
	setChromeCookies(t, browserCtx, primary, client.Jar.Cookies(mustURL(t, primary+"/auth/v1/users/")))

	// Chrome itself rejects mismatched origin and RP ID before a credential is
	// created. This is a deterministic client-side negative proof, not timing.
	assertCreateRejected(t, browserCtx, "http://127.0.0.1:"+mustURL(t, primary).Port(), registration)
	assertCreateRejected(t, browserCtx, primary, replaceRPID(registration, "invalid.example.test"))

	created := webauthnCreate(t, browserCtx, primary, registration)
	finishRegistration(t, client, primary, subject, csrf, created)
	credentials := auth.credentials(t)
	if len(credentials) != 1 {
		t.Fatalf("registration credential count=%d, want 1", len(credentials))
	}
	if os.Getenv(passkeyCaseEnv) == forcedMFACase {
		assertForcedMFABootstrapClient(t, browserCtx, auth, client, primary, secondary, tertiary, username, password)
		return
	}

	// Once a passkey exists, Rauthy requires a fresh WebAuthn mfa_code instead
	// of the password. Exercise the proof, exchange and final-token CAS across
	// all three pods before changing the account mode.
	if status, _ := modificationToken(t, client, primary, subject, csrf, map[string]string{"password": password}); status != http.StatusBadRequest {
		t.Fatalf("password modification token after registration status=%d, want 400", status)
	}
	mfaStart := beginMFAProof(t, client, secondary, subject, csrf)
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(c context.Context) error {
		return cdpwebauthn.SetResponseOverrideBits(auth.id).WithIsBadUV(true).Do(c)
	})); err != nil {
		t.Fatal(err)
	}
	badMFAAssertion := webauthnGet(t, browserCtx, tertiary, mfaStart.RCR)
	if status, _ := finishMFAProof(t, client, tertiary, subject, csrf, mfaStart.Code, badMFAAssertion); status != http.StatusBadRequest {
		t.Fatalf("MFA bad-UV finish status=%d, want 400", status)
	}
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(c context.Context) error {
		return cdpwebauthn.SetResponseOverrideBits(auth.id).WithIsBadUV(false).Do(c)
	})); err != nil {
		t.Fatal(err)
	}

	mfaStart = beginMFAProof(t, client, secondary, subject, csrf)
	mfaAssertion := webauthnGet(t, browserCtx, tertiary, mfaStart.RCR)
	if status, proof := finishMFAProof(t, client, tertiary, subject, csrf, mfaStart.Code, mfaAssertion); status != http.StatusAccepted || len(proof.Code) != 48 || proof.UserID != subject {
		t.Fatalf("MFA finish status=%d proof=%+v, want 202 and bound 48-char code", status, proof)
	} else if status, token := modificationToken(t, client, primary, subject, csrf, map[string]string{"mfa_code": proof.Code}); status != http.StatusOK || len(token) != 32 {
		t.Fatalf("MFA proof exchange status=%d token length=%d, want 200 and 32", status, len(token))
	} else {
		if status, _ := modificationToken(t, client, secondary, subject, csrf, map[string]string{"mfa_code": proof.Code}); status != http.StatusBadRequest {
			t.Fatalf("MFA proof exchange replay status=%d, want 400", status)
		}
		if registration := beginRegistrationNamed(t, client, tertiary, subject, csrf, "Chrome backup", token); len(registration) == 0 {
			t.Fatal("backup registration start returned no options")
		}
		if status := beginRegistrationStatus(t, client, primary, subject, csrf, "Chrome backup replay", token); status != http.StatusUnauthorized {
			t.Fatalf("MFA modification token replay status=%d, want 401", status)
		}
	}

	// Convert through pod B with the pre-conversion browser session. The same
	// session must remain usable, but password authentication must not.
	conversionCSRF := accountCSRF(t, client, secondary)
	if status, size := convertPasskey(t, client, secondary, subject, conversionCSRF); status != http.StatusOK || size != 0 {
		t.Fatalf("passkey conversion status=%d body bytes=%d, want 200 empty", status, size)
	}
	if status, _ := convertPasskey(t, client, secondary, subject, conversionCSRF); status != http.StatusBadRequest {
		t.Fatalf("passkey conversion replay status=%d, want 400", status)
	}
	// Rauthy parity: conversion preserves established browser/OAuth sessions.
	_ = accountCSRF(t, client, primary)
	if status := passwordLoginStatus(t, browserClient(t), tertiary, username, password, "passkey-password-disabled"); status != http.StatusUnauthorized {
		t.Fatalf("fresh password login after conversion status=%d, want 401", status)
	}

	// Browser-button E2E: after conversion the production inline JS must
	// complete a real passkey login via #passkey-btn.  Clear Chrome cookies
	// first so the redirect proves a fresh credential ceremony, not a
	// pre-existing session.
	beforeCounter := credentials[0].SignCount
	assertBrowserPasskeyButtonLogin(t, browserCtx, primary, username, "btn-e2e-state", beforeCounter, auth)

	// Rauthy's reverse conversion is authorized by a distinct, UV WebAuthn
	// PasswordNew proof. Keep the browser session across all three pods: the
	// completed password update must not invalidate that established session.
	reverseCSRF := accountCSRF(t, client, secondary)
	reverseStart := beginMFAProofPurpose(t, client, secondary, subject, reverseCSRF, "PasswordNew")
	reverseAssertion := webauthnGet(t, browserCtx, tertiary, reverseStart.RCR)
	if status, reverseProof := finishMFAProof(t, client, tertiary, subject, reverseCSRF, reverseStart.Code, reverseAssertion); status != http.StatusAccepted || len(reverseProof.Code) != 48 || reverseProof.UserID != subject {
		t.Fatalf("PasswordNew finish status=%d proof=%+v, want 202 and bound 48-char code", status, reverseProof)
	} else {
		const reversedPassword = "ReversedPassword2"
		if status := putPasskeyPassword(t, client, tertiary, subject, reverseCSRF, reversedPassword, reverseProof.Code); status != http.StatusOK {
			t.Fatalf("passkey reverse conversion status=%d, want 200", status)
		}
		if status := putPasskeyPassword(t, client, secondary, subject, reverseCSRF, reversedPassword, reverseProof.Code); status != http.StatusBadRequest {
			t.Fatalf("PasswordNew proof replay status=%d, want 400", status)
		}
		if status := passwordLoginStatus(t, browserClient(t), primary, username, reversedPassword, "passkey-password-restored"); status != http.StatusSeeOther && status != http.StatusFound {
			t.Fatalf("fresh password login after reverse conversion status=%d", status)
		}
	}
	_ = accountCSRF(t, client, primary)

	// A bad UV assertion is rejected after conversion; the subsequent valid
	// passwordless ceremony is independent and proves the existing passkey
	// remains usable after reverse conversion.
	noUV := passwordlessClient(t, client, secondary)
	noUVStart := beginLogin(t, noUV, secondary, "passkey-no-uv")
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(c context.Context) error {
		return cdpwebauthn.SetResponseOverrideBits(auth.id).WithIsBadUV(true).Do(c)
	})); err != nil {
		t.Fatal(err)
	}
	noUVAssertion := webauthnGet(t, browserCtx, secondary, noUVStart.RCR)
	if status := finishLogin(t, noUV, secondary, noUVStart.Code, noUVAssertion); status != http.StatusUnauthorized {
		t.Fatalf("UV-less assertion status=%d, want 401", status)
	}
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(c context.Context) error {
		return cdpwebauthn.SetResponseOverrideBits(auth.id).WithIsBadUV(false).Do(c)
	})); err != nil {
		t.Fatal(err)
	}

	login := passwordlessClient(t, client, secondary)
	start := beginLogin(t, login, secondary, "passkey-login")
	before := credentials[0].SignCount
	assertion := webauthnGet(t, browserCtx, secondary, start.RCR)
	if status := finishLogin(t, login, secondary, start.Code, assertion); status != http.StatusSeeOther && status != http.StatusFound {
		t.Fatalf("passwordless login on pod B status=%d", status)
	}
	after := auth.credentials(t)
	if len(after) != 1 || after[0].SignCount <= before {
		t.Fatalf("assertion did not advance authenticator counter: before=%d after=%+v", before, after)
	}

	// Pod C sees the shared session/ceremony state and rejects the exact replay.
	// A 403 is expected because the successful ceremony revoked its init session.
	replay := cloneCookies(t, login, tertiary)
	if status := finishLogin(t, replay, tertiary, start.Code, assertion); status != http.StatusForbidden {
		t.Fatalf("pod C replay status=%d, want 403", status)
	}
}

type loginStart struct {
	Code string          `json:"code"`
	RCR  json.RawMessage `json:"rcr"`
}
type mfaProof struct {
	Code   string `json:"code"`
	UserID string `json:"user_id"`
}

// assertForcedMFABootstrapClient covers the only configured force_mfa policy.
// Dynamic registration intentionally cannot set this Rauthy static-client field.
func assertForcedMFABootstrapClient(t *testing.T, browserCtx context.Context, auth *virtualAuthenticator, established *http.Client, primary, secondary, tertiary, username, password string) {
	t.Helper()
	const clientID = "goauthy-dev"
	const redirectURI = "http://localhost:5555/callback"

	// A password-only session cannot satisfy the bootstrap client's forced MFA.
	pwdReuse := cloneCookies(t, established, primary)
	_ = beginDynamicAuthorization(t, pwdReuse, tertiary, clientID, redirectURI, "forced-password-session", "")

	stepUp := browserClient(t)
	interaction := beginDynamicAuthorization(t, stepUp, primary, clientID, redirectURI, "forced-mfa-bad", "")
	badStart := passwordForcedMFA(t, stepUp, secondary, interaction, username, password)
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(c context.Context) error {
		return cdpwebauthn.SetResponseOverrideBits(auth.id).WithIsBadUV(true).Do(c)
	})); err != nil {
		t.Fatal(err)
	}
	badAssertion := webauthnGet(t, browserCtx, primary, badStart.RCR)
	if response := finishForcedMFA(t, stepUp, tertiary, badStart.Code, badAssertion); response.StatusCode != http.StatusUnauthorized || response.Header.Get("Location") != "" || len(response.Cookies()) != 0 {
		response.Body.Close()
		t.Fatalf("forced MFA bad-UV finish status=%d location=%q cookies=%d, want 401 without code or session", response.StatusCode, response.Header.Get("Location"), len(response.Cookies()))
	} else {
		response.Body.Close()
	}
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(c context.Context) error {
		return cdpwebauthn.SetResponseOverrideBits(auth.id).WithIsBadUV(false).Do(c)
	})); err != nil {
		t.Fatal(err)
	}

	// A fresh password interaction creates a distinct forced-MFA ceremony on
	// pod B; pod C completes it. The old init session must reject replay.
	stepUp = browserClient(t)
	interaction = beginDynamicAuthorization(t, stepUp, primary, clientID, redirectURI, "forced-mfa", "")
	start := passwordForcedMFA(t, stepUp, secondary, interaction, username, password)
	replay := cloneCookies(t, stepUp, tertiary)
	assertion := webauthnGet(t, browserCtx, primary, start.RCR)
	response := finishForcedMFA(t, stepUp, tertiary, start.Code, assertion)
	code := assertAuthorizationResponse(t, response, "forced-mfa")
	response.Body.Close()
	assertMFAIDToken(t, browserClient(t), secondary, primary, clientID, redirectURI, code, "correct-horse-battery-staple")
	if response = finishForcedMFA(t, replay, primary, start.Code, assertion); response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("forced MFA replay status=%d, want 403", response.StatusCode)
	} else {
		response.Body.Close()
	}
	assertAuthorizationRedirect(t, stepUp, secondary, clientID, redirectURI, "forced-mfa-none", "none")

	// A password-only session is never sufficient for this client, even after
	// another successful MFA session exists elsewhere in the browser store.
	freshPassword := browserClient(t)
	interaction = beginDynamicAuthorization(t, freshPassword, primary, clientID, redirectURI, "forced-mfa-fresh-password", "")
	_ = passwordForcedMFA(t, freshPassword, secondary, interaction, username, password)
}

// assertBrowserPasskeyButtonLogin exercises the production login page's
// #passkey-btn through real inline JavaScript.  It clears Chrome cookies,
// navigates to an OIDC authorize URL, fills the username field, and clicks
// the passkey button.  The production JS performs fetch(webauthn_start),
// navigator.credentials.get (served by the virtual authenticator), and a
// native form POST to webauthn_finish which redirects to the registered
// callback.  A network.EventRequestWillBeSent listener captures that
// redirect and asserts non-empty code, exact state, and no error.
func assertBrowserPasskeyButtonLogin(t *testing.T, browserCtx context.Context, base, username, state string, wantAfterCounter int64, auth *virtualAuthenticator) {
	t.Helper()
	// Clear all Chrome cookies so the login is a fresh credential ceremony.
	if err := chromedp.Run(browserCtx, network.ClearBrowserCookies()); err != nil {
		t.Fatal(err)
	}
	// Verify no cookies remain for the origin.
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(c context.Context) error {
		cookies, err := network.GetCookies().WithURLs([]string{base + "/"}).Do(c)
		if err != nil {
			return err
		}
		if len(cookies) != 0 {
			return fmt.Errorf("cookies remain after clear: %d", len(cookies))
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}

	authorizeURL := base + "/oidc/authorize?response_type=code&client_id=goauthy-dev&redirect_uri=" + url.QueryEscape(defaultRedirect) + "&scope=openid+goauthy.read&state=" + url.QueryEscape(state) + "&nonce=" + url.QueryEscape(state) + "&code_challenge=" + strings.Repeat("c", 43) + "&code_challenge_method=S256"

	type redirectResult struct {
		location *url.URL
	}
	redirect := make(chan redirectResult, 1)
	chromedp.ListenTarget(browserCtx, func(ev interface{}) {
		req, ok := ev.(*network.EventRequestWillBeSent)
		if !ok {
			return
		}
		if req.Request.Method != "GET" {
			return
		}
		loc, err := url.Parse(req.Request.URL)
		if err != nil || loc.Host != "localhost:5555" || loc.Path != "/callback" {
			return
		}
		select {
		case redirect <- redirectResult{location: loc}:
		default:
		}
	})

	if err := chromedp.Run(browserCtx,
		chromedp.Navigate(authorizeURL),
		chromedp.WaitVisible(`input[name="username"]`),
		chromedp.SetValue(`input[name="username"]`, username),
		chromedp.Click(`#passkey-btn`),
	); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-redirect:
		code := result.location.Query().Get("code")
		gotState := result.location.Query().Get("state")
		errParam := result.location.Query().Get("error")
		if code == "" {
			t.Fatalf("passkey button login: empty code in callback %s", result.location)
		}
		if gotState != state {
			t.Fatalf("passkey button login: state=%q want=%q", gotState, state)
		}
		if errParam != "" {
			t.Fatalf("passkey button login: error=%q in callback", errParam)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("passkey button login: timed out waiting for callback redirect")
	}

	// The virtual authenticator counter must have advanced.
	after := auth.credentials(t)
	if len(after) != 1 || after[0].SignCount <= wantAfterCounter {
		t.Fatalf("passkey button login: counter did not advance: before=%d after=%+v", wantAfterCounter, after)
	}
}

func dynamicAuthorizationURL(base, clientID, redirectURI, state, prompt string) string {
	digest := sha256.Sum256([]byte(dynamicVerifier))
	values := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {"openid goauthy.read"}, "state": {state}, "nonce": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	if prompt != "" {
		values.Set("prompt", prompt)
	}
	return base + "/oidc/authorize?" + values.Encode()
}

func beginDynamicAuthorization(t *testing.T, client *http.Client, base, clientID, redirectURI, state, prompt string) string {
	t.Helper()
	response := do(t, client, http.MethodGet, dynamicAuthorizationURL(base, clientID, redirectURI, state, prompt), nil, nil)
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("forced MFA authorize status=%d err=%v", response.StatusCode, err)
	}
	match := loginInteraction.FindStringSubmatch(string(body))
	if len(match) != 2 {
		t.Fatal("forced MFA authorize interaction missing")
	}
	return match[1]
}

func passwordForcedMFA(t *testing.T, client *http.Client, base, interaction, username, password string) loginStart {
	t.Helper()
	response := passwordForcedMFAResponse(t, client, base, interaction, username, password)
	defer response.Body.Close()
	var result loginStart
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") || response.Header.Get("Location") != "" || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result) != nil || result.Code == "" || len(result.RCR) == 0 {
		t.Fatalf("forced MFA password login status=%d content-type=%q location=%q", response.StatusCode, response.Header.Get("Content-Type"), response.Header.Get("Location"))
	}
	return result
}

func passwordForcedMFAResponse(t *testing.T, client *http.Client, base, interaction, username, password string) *http.Response {
	t.Helper()
	form := url.Values{"interaction": {interaction}, "username": {username}, "password": {password}}
	return do(t, client, http.MethodPost, base+"/auth/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
}

func finishForcedMFA(t *testing.T, client *http.Client, base, code string, assertion json.RawMessage) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{"code": code, "data": string(assertion)})
	if err != nil {
		t.Fatal(err)
	}
	return do(t, client, http.MethodPost, base+"/auth/v1/users/webauthn_finish", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
}

func assertAuthorizationRedirect(t *testing.T, client *http.Client, base, clientID, redirectURI, state, prompt string) {
	t.Helper()
	response := do(t, client, http.MethodGet, dynamicAuthorizationURL(base, clientID, redirectURI, state, prompt), nil, nil)
	defer response.Body.Close()
	assertAuthorizationResponse(t, response, state)
}

func assertAuthorizationResponse(t *testing.T, response *http.Response, state string) string {
	t.Helper()
	location, err := url.Parse(response.Header.Get("Location"))
	if (response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther) || err != nil || location.Query().Get("state") != state || location.Query().Get("code") == "" || location.Query().Get("error") != "" {
		t.Fatalf("authorization status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	return location.Query().Get("code")
}

func assertMFAIDToken(t *testing.T, client *http.Client, tokenBase, issuer, clientID, redirectURI, code, clientSecret string) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {dynamicVerifier}}
	response := do(t, client, http.MethodPost, tokenBase+"/oidc/token", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))})
	defer response.Body.Close()
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&tokens) != nil || tokens.IDToken == "" {
		t.Fatalf("forced MFA token status=%d", response.StatusCode)
	}
	issuedAt, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil {
		t.Fatalf("forced MFA token Date header: %v", err)
	}
	jwksResponse := do(t, client, http.MethodGet, tokenBase+"/oidc/jwks.json", nil, nil)
	defer jwksResponse.Body.Close()
	var keys jose.JSONWebKeySet
	if jwksResponse.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(jwksResponse.Body, 64<<10)).Decode(&keys) != nil || len(keys.Keys) == 0 {
		t.Fatalf("forced MFA JWKS status=%d", jwksResponse.StatusCode)
	}
	claims, err := oidc.VerifyIDToken(tokens.IDToken, keys, issuer, clientID, issuedAt)
	if err != nil || strings.Join(claims.AuthenticationMethods, ",") != "mfa" {
		t.Fatalf("forced MFA ID token amr=%v err=%v", claims.AuthenticationMethods, err)
	}
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	t.Skipf("set %s for passkey E2E", name)
	return ""
}
func requiredURL(t *testing.T, name string) string {
	return strings.TrimRight(requiredEnv(t, name), "/")
}
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func browserClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, client *http.Client, method, target string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func loginPassword(t *testing.T, client *http.Client, base, username, password, state string) {
	t.Helper()
	if status := passwordLoginStatus(t, client, base, username, password, state); status != http.StatusSeeOther && status != http.StatusFound {
		t.Fatalf("password login status=%d", status)
	}
}

func passwordLoginStatus(t *testing.T, client *http.Client, base, username, password, state string) int {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/oidc/authorize?response_type=code&client_id=goauthy-dev&redirect_uri="+url.QueryEscape(defaultRedirect)+"&scope=goauthy.read&state="+url.QueryEscape(state)+"&code_challenge="+strings.Repeat("a", 43)+"&code_challenge_method=S256", nil, nil)
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("authorize status=%d read=%v", response.StatusCode, err)
	}
	match := loginInteraction.FindStringSubmatch(string(body))
	if len(match) != 2 {
		t.Fatal("authorize interaction missing")
	}
	form := url.Values{"interaction": {match[1]}, "username": {username}, "password": {password}}
	response = do(t, client, http.MethodPost, base+"/auth/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
	response.Body.Close()
	return response.StatusCode
}

func accountCSRF(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/account/password", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var doc struct {
		CSRF string `json:"csrf_token"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&doc) != nil || doc.CSRF == "" {
		t.Fatalf("account csrf status=%d", response.StatusCode)
	}
	return doc.CSRF
}
func issueModification(t *testing.T, client *http.Client, base, subject, csrf, password string) string {
	t.Helper()
	status, id := modificationToken(t, client, base, subject, csrf, map[string]string{"password": password})
	if status != http.StatusOK || id == "" {
		t.Fatalf("modification token status=%d", status)
	}
	return id
}
func modificationToken(t *testing.T, client *http.Client, base, subject, csrf string, payload map[string]string) (int, string) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+url.PathEscape(subject)+"/mfa_token", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	defer response.Body.Close()
	var doc struct {
		ID string `json:"id"`
	}
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, ""
	}
	if err := json.NewDecoder(response.Body).Decode(&doc); err != nil || doc.ID == "" {
		t.Fatalf("modification token response: %v", err)
	}
	return response.StatusCode, doc.ID
}
func beginRegistration(t *testing.T, client *http.Client, base, subject, csrf, token string) json.RawMessage {
	return beginRegistrationNamed(t, client, base, subject, csrf, "Chrome 151", token)
}
func beginRegistrationNamed(t *testing.T, client *http.Client, base, subject, csrf, name, token string) json.RawMessage {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"passkey_name": name, "mfa_mod_token_id": token})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+url.PathEscape(subject)+"/webauthn/register/start", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK || err != nil || len(raw) == 0 {
		t.Fatalf("registration start status=%d err=%v", response.StatusCode, err)
	}
	return raw
}
func beginRegistrationStatus(t *testing.T, client *http.Client, base, subject, csrf, name, token string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"passkey_name": name, "mfa_mod_token_id": token})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+url.PathEscape(subject)+"/webauthn/register/start", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	response.Body.Close()
	return response.StatusCode
}
func beginMFAProof(t *testing.T, client *http.Client, base, subject, csrf string) loginStart {
	return beginMFAProofPurpose(t, client, base, subject, csrf, "MfaModToken")
}
func beginMFAProofPurpose(t *testing.T, client *http.Client, base, subject, csrf, purpose string) loginStart {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"purpose": purpose})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+url.PathEscape(subject)+"/webauthn/auth/start", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	defer response.Body.Close()
	var result loginStart
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result) != nil || result.Code == "" || len(result.RCR) == 0 {
		t.Fatalf("MFA WebAuthn start status=%d", response.StatusCode)
	}
	return result
}
func putPasskeyPassword(t *testing.T, client *http.Client, base, subject, csrf, password, proof string) int {
	t.Helper()
	body, err := json.Marshal(map[string]string{"password_new": password, "mfa_code": proof})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPut, base+"/auth/v1/users/"+url.PathEscape(subject)+"/self", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	response.Body.Close()
	return response.StatusCode
}
func finishMFAProof(t *testing.T, client *http.Client, base, subject, csrf, code string, assertion json.RawMessage) (int, mfaProof) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"code": code, "data": json.RawMessage(assertion)})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+url.PathEscape(subject)+"/webauthn/auth/finish", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return response.StatusCode, mfaProof{}
	}
	var proof mfaProof
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&proof); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, proof
}
func finishRegistration(t *testing.T, client *http.Client, base, subject, csrf string, data json.RawMessage) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"passkey_name": "Chrome 151", "data": json.RawMessage(data)})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+url.PathEscape(subject)+"/webauthn/register/finish", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("registration finish status=%d", response.StatusCode)
	}
}
func convertPasskey(t *testing.T, client *http.Client, base, subject, csrf string) (int, int) {
	t.Helper()
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+url.PathEscape(subject)+"/self/convert_passkey", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, len(body)
}
func passwordlessClient(t *testing.T, from *http.Client, base string) *http.Client {
	t.Helper()
	to := browserClient(t)
	source := mustURL(t, base+"/auth")
	for _, cookie := range from.Jar.Cookies(source) {
		if cookie.Name == "goauthy-passkey" || cookie.Name == "__Host-goauthy-passkey" {
			to.Jar.SetCookies(source, []*http.Cookie{cookie})
			return to
		}
	}
	t.Fatal("passwordless cookie missing")
	return nil
}
func cloneCookies(t *testing.T, from *http.Client, base string) *http.Client {
	t.Helper()
	to := browserClient(t)
	u := mustURL(t, base+"/auth")
	to.Jar.SetCookies(u, from.Jar.Cookies(u))
	return to
}
func beginLogin(t *testing.T, client *http.Client, base, state string) loginStart {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/oidc/authorize?response_type=code&client_id=goauthy-dev&redirect_uri="+url.QueryEscape(defaultRedirect)+"&scope=goauthy.read&state="+url.QueryEscape(state)+"&code_challenge="+strings.Repeat("b", 43)+"&code_challenge_method=S256", nil, nil)
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("passkey authorize status=%d err=%v", response.StatusCode, err)
	}
	match := loginInteraction.FindStringSubmatch(string(body))
	if len(match) != 2 {
		t.Fatal("passkey authorize interaction missing")
	}
	request, _ := json.Marshal(map[string]any{"purpose": map[string]string{"Login": match[1]}})
	response = do(t, client, http.MethodPost, base+"/auth/v1/users/webauthn_start", bytes.NewReader(request), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var result loginStart
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result) != nil || result.Code == "" || len(result.RCR) == 0 {
		t.Fatalf("passkey start status=%d", response.StatusCode)
	}
	return result
}
func finishLogin(t *testing.T, client *http.Client, base, code string, assertion json.RawMessage) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"code": code, "data": string(assertion)})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/webauthn_finish", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	response.Body.Close()
	return response.StatusCode
}

type virtualAuthenticator struct {
	ctx                 context.Context
	id                  cdpwebauthn.AuthenticatorID
	cancel, cancelAlloc context.CancelFunc
}

func newVirtualAuthenticator(t *testing.T, parent context.Context) *virtualAuthenticator {
	t.Helper()
	alloc, cancelAlloc := chromedp.NewExecAllocator(parent, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", true), chromedp.Flag("no-first-run", true))...)
	ctx, cancel := chromedp.NewContext(alloc)
	a := &virtualAuthenticator{ctx: ctx, cancel: cancel, cancelAlloc: cancelAlloc}
	t.Cleanup(func() { cancel(); cancelAlloc() })
	if err := chromedp.Run(ctx); err != nil {
		t.Fatalf("Chrome unavailable for explicitly enabled passkey E2E: %v", err)
	}
	var product string
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
		var err error
		_, product, _, _, _, err = browser.GetVersion().Do(c)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	// Exercise the required CDP capabilities below; a hard-coded major version
	// silently skipped otherwise compatible browsers after an automatic update.
	t.Logf("passkey virtual authenticator browser: %s", product)
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
		if err := cdpwebauthn.Enable().Do(c); err != nil {
			return err
		}
		var err error
		a.id, err = cdpwebauthn.AddVirtualAuthenticator(&cdpwebauthn.VirtualAuthenticatorOptions{Protocol: cdpwebauthn.AuthenticatorProtocolCtap2, Ctap2version: cdpwebauthn.Ctap2versionCtap21, Transport: cdpwebauthn.AuthenticatorTransportInternal, HasResidentKey: true, HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true}).Do(c)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	return a
}
func (a *virtualAuthenticator) close() {
	_ = chromedp.Run(a.ctx, chromedp.ActionFunc(func(c context.Context) error { return cdpwebauthn.Disable().Do(c) }))
	a.cancel()
	a.cancelAlloc()
}
func (a *virtualAuthenticator) credentials(t *testing.T) []*cdpwebauthn.Credential {
	t.Helper()
	var credentials []*cdpwebauthn.Credential
	if err := chromedp.Run(a.ctx, chromedp.ActionFunc(func(c context.Context) error {
		var err error
		credentials, err = cdpwebauthn.GetCredentials(a.id).Do(c)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	return credentials
}

func setChromeCookies(t *testing.T, ctx context.Context, base string, cookies []*http.Cookie) {
	t.Helper()
	if err := chromedp.Run(ctx, chromedp.Navigate(base)); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range cookies {
		c := cookie
		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(x context.Context) error {
			return network.SetCookie(c.Name, c.Value).WithURL(base + c.Path).WithHTTPOnly(c.HttpOnly).WithSecure(c.Secure).Do(x)
		})); err != nil {
			t.Fatal(err)
		}
	}
}
func replaceRPID(raw json.RawMessage, rpID string) json.RawMessage {
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	if rp, ok := value["publicKey"].(map[string]any); ok {
		if entity, ok := rp["rp"].(map[string]any); ok {
			entity["id"] = rpID
		}
	}
	out, _ := json.Marshal(value)
	return out
}
func assertCreateRejected(t *testing.T, ctx context.Context, origin string, options json.RawMessage) {
	t.Helper()
	if err := chromedp.Run(ctx, chromedp.Navigate(origin)); err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	err := evaluatePromise(ctx, createJS(options), &result)
	if err != nil {
		t.Fatal(err)
	}
	if result["error"] == "" {
		t.Fatalf("WebAuthn create unexpectedly accepted wrong origin/RP: %s", origin)
	}
}
func webauthnCreate(t *testing.T, ctx context.Context, base string, options json.RawMessage) json.RawMessage {
	t.Helper()
	if err := chromedp.Run(ctx, chromedp.Navigate(base)); err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if err := evaluatePromise(ctx, createJS(options), &result); err != nil {
		t.Fatal(err)
	}
	if len(result["credential"]) == 0 {
		t.Fatalf("WebAuthn create failed: %s", result["error"])
	}
	return result["credential"]
}
func webauthnGet(t *testing.T, ctx context.Context, base string, options json.RawMessage) json.RawMessage {
	t.Helper()
	if err := chromedp.Run(ctx, chromedp.Navigate(base)); err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if err := evaluatePromise(ctx, getJS(options), &result); err != nil {
		t.Fatal(err)
	}
	if len(result["credential"]) == 0 {
		t.Fatalf("WebAuthn get failed: %s", result["error"])
	}
	return result["credential"]
}
func evaluatePromise(ctx context.Context, expression string, result any) error {
	var raw *runtime.RemoteObject
	action := chromedp.ActionFunc(func(c context.Context) error {
		value, exception, err := runtime.Evaluate(expression).WithAwaitPromise(true).WithReturnByValue(true).Do(c)
		if err != nil {
			return err
		}
		if exception != nil {
			return fmt.Errorf("browser exception: %s", exception.Text)
		}
		raw = value
		return nil
	})
	if err := chromedp.Run(ctx, action); err != nil {
		return err
	}
	return json.Unmarshal(raw.Value, result)
}
func createJS(options json.RawMessage) string { return credentialJS("create", options) }
func getJS(options json.RawMessage) string    { return credentialJS("get", options) }
func credentialJS(method string, options json.RawMessage) string {
	return `(async()=>{const o=` + string(options) + `;const b=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));const p=o.publicKey;p.challenge=b(p.challenge);if(p.user)p.user.id=b(p.user.id);for(const x of (p.excludeCredentials||p.allowCredentials||[]))x.id=b(x.id);try{const c=await navigator.credentials.` + method + `(o);const r=c.response;const e=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');return {credential:{id:c.id,rawId:e(c.rawId),type:c.type,response:{clientDataJSON:e(r.clientDataJSON),attestationObject:r.attestationObject?e(r.attestationObject):undefined,authenticatorData:r.authenticatorData?e(r.authenticatorData):undefined,signature:r.signature?e(r.signature):undefined,userHandle:r.userHandle?e(r.userHandle):undefined}}}}catch(e){return {error:e.name}}})()`
}

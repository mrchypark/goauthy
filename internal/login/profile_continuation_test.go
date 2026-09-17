package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestPasswordLoginMissingProfileYieldsProfileContinuation(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "profile-recovery-email", SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('user-1','alice@example.test')`}); err != nil {
		t.Fatal(err)
	}
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.SetUserValuesPolicy(policy, h.identity.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	// alice has no given_name in profile -> triggers profile continuation
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	loginResp := httptest.NewRecorder()
	h.Login(loginResp, postLogin(init, interaction, "alice", "correct password"))
	if loginResp.Code != http.StatusSeeOther && loginResp.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%q", loginResp.Code, loginResp.Body.String())
	}
	location := loginResp.Header().Get("Location")
	if !strings.HasPrefix(location, "/auth/profile?interaction=") {
		t.Fatalf("expected profile redirect, got %q", location)
	}
	profileCookie := loginResp.Result().Cookies()[0]

	// GET /auth/profile should render form with required given_name field
	getReq := httptest.NewRequest(http.MethodGet, location, nil)
	getReq.AddCookie(profileCookie)
	getResp := httptest.NewRecorder()
	h.Profile(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("profile GET status=%d body=%q", getResp.Code, getResp.Body.String())
	}
	body := getResp.Body.String()
	if !strings.Contains(body, `name="given_name"`) {
		t.Fatalf("profile form missing given_name: %s", body)
	}
	if !strings.Contains(body, `required`) {
		t.Fatalf("profile form missing required attribute: %s", body)
	}

	// Extract CSRF token and interaction from form
	csrfMatch := fedCMCSRFPattern.FindStringSubmatch(body)
	if len(csrfMatch) < 2 {
		t.Fatalf("could not extract CSRF token from profile form: %s", body)
	}
	interactionMatch := interactionPattern.FindStringSubmatch(body)
	if len(interactionMatch) < 2 {
		t.Fatalf("could not extract interaction from profile form: %s", body)
	}

	// POST with valid given_name, empty optional fields
	form := url.Values{
		"csrf_token":  {csrfMatch[1]},
		"interaction": {interactionMatch[1]},
		"given_name":  {"Alice"},
		"family_name": {""},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionMatch[1], strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	postResp := httptest.NewRecorder()
	h.Profile(postResp, postReq)
	if postResp.Code != http.StatusSeeOther {
		t.Fatalf("profile POST status=%d body=%q", postResp.Code, postResp.Body.String())
	}
	postLocation := postResp.Header().Get("Location")
	if !strings.Contains(postLocation, "code=") {
		t.Fatalf("expected code redirect after profile submission, got %q", postLocation)
	}
}

func TestAuthenticatedSessionRetainedAfterProfileSubmission(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "profile-recovery-email", SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('user-1','alice@example.test')`}); err != nil {
		t.Fatal(err)
	}
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.SetUserValuesPolicy(policy, h.identity.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	loginResp := httptest.NewRecorder()
	h.Login(loginResp, postLogin(init, interaction, "alice", "correct password"))
	profileCookie := loginResp.Result().Cookies()[0]
	location := loginResp.Header().Get("Location")

	// Record session ID and creation time before profile submission
	sessionBefore, err := h.browser.LoadSession(context.Background(), profileCookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	// GET profile form
	getReq := httptest.NewRequest(http.MethodGet, location, nil)
	getReq.AddCookie(profileCookie)
	getResp := httptest.NewRecorder()
	h.Profile(getResp, getReq)
	body := getResp.Body.String()
	csrfMatch := fedCMCSRFPattern.FindStringSubmatch(body)
	if len(csrfMatch) < 2 {
		t.Fatalf("could not extract CSRF token from profile form: %s", body)
	}
	interactionMatch := interactionPattern.FindStringSubmatch(body)
	if len(interactionMatch) < 2 {
		t.Fatalf("could not extract interaction from profile form: %s", body)
	}
	csrf := csrfMatch[1]
	interactionToken := interactionMatch[1]

	// POST profile
	form := url.Values{"csrf_token": {csrf}, "interaction": {interactionToken}, "given_name": {"Alice"}}
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	postResp := httptest.NewRecorder()
	h.Profile(postResp, postReq)
	if postResp.Code != http.StatusSeeOther {
		t.Fatalf("profile POST status=%d", postResp.Code)
	}

	// Verify same session ID and CreatedAt retained
	sessionAfter, err := h.browser.LoadSession(context.Background(), profileCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if sessionBefore.ID != sessionAfter.ID {
		t.Fatalf("session ID changed: before=%s after=%s", sessionBefore.ID, sessionAfter.ID)
	}
	if !sessionBefore.CreatedAt.Equal(sessionAfter.CreatedAt) {
		t.Fatalf("session CreatedAt changed: before=%s after=%s", sessionBefore.CreatedAt, sessionAfter.CreatedAt)
	}
}

func TestRepeatedProfilePOSTRefusesAndNoMutation(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "profile-recovery-email", SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('user-1','alice@example.test')`}); err != nil {
		t.Fatal(err)
	}
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.SetUserValuesPolicy(policy, h.identity.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	loginResp := httptest.NewRecorder()
	h.Login(loginResp, postLogin(init, interaction, "alice", "correct password"))
	profileCookie := loginResp.Result().Cookies()[0]
	location := loginResp.Header().Get("Location")

	// GET profile form
	getReq := httptest.NewRequest(http.MethodGet, location, nil)
	getReq.AddCookie(profileCookie)
	getResp := httptest.NewRecorder()
	h.Profile(getResp, getReq)
	body := getResp.Body.String()
	csrfMatch := fedCMCSRFPattern.FindStringSubmatch(body)
	if len(csrfMatch) < 2 {
		t.Fatalf("could not extract CSRF token from profile form: %s", body)
	}
	interactionMatch := interactionPattern.FindStringSubmatch(body)
	if len(interactionMatch) < 2 {
		t.Fatalf("could not extract interaction from profile form: %s", body)
	}
	csrf := csrfMatch[1]
	interactionToken := interactionMatch[1]

	// First POST - should succeed
	form := url.Values{"csrf_token": {csrf}, "interaction": {interactionToken}, "given_name": {"Alice"}}
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	postResp := httptest.NewRecorder()
	h.Profile(postResp, postReq)
	if postResp.Code != http.StatusSeeOther {
		t.Fatalf("first profile POST status=%d", postResp.Code)
	}

	// Second POST with same interaction - should fail (consumed)
	repeatReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(form.Encode()))
	repeatReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	repeatReq.Header.Set("Sec-Fetch-Site", "same-origin")
	repeatReq.AddCookie(profileCookie)
	repeatResp := httptest.NewRecorder()
	h.Profile(repeatResp, repeatReq)
	if repeatResp.Code == http.StatusSeeOther || repeatResp.Code == http.StatusFound {
		t.Fatalf("repeat POST should not succeed: status=%d", repeatResp.Code)
	}

	// Verify profile was not mutated by second attempt
	claims, err := h.identity.ProfileClaimsBySubject(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.GivenName == nil || *claims.GivenName != "Alice" {
		t.Fatalf("profile given_name=%v", claims.GivenName)
	}
}

// profileSetup is a small local helper that performs the common fixture flow:
// recovery email insert, policy registration, authorize→login→profile redirect,
// and returns the profile cookie, the redirect location, and the DB handle.
func profileSetup(t *testing.T) (*Handler, *rhiza.DB, *http.Cookie, string) {
	t.Helper()
	h, db := testHandlerWithDB(t, false)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "profile-recovery-email", SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('user-1','alice@example.test')`}); err != nil {
		t.Fatal(err)
	}
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.SetUserValuesPolicy(policy, h.identity.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	loginResp := httptest.NewRecorder()
	h.Login(loginResp, postLogin(init, interaction, "alice", "correct password"))
	if loginResp.Code != http.StatusSeeOther && loginResp.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%q", loginResp.Code, loginResp.Body.String())
	}
	location := loginResp.Header().Get("Location")
	if !strings.HasPrefix(location, "/auth/profile?interaction=") {
		t.Fatalf("expected profile redirect, got %q", location)
	}
	profileCookie := loginResp.Result().Cookies()[0]
	return h, db, profileCookie, location
}

// profileGETFields performs GET /auth/profile and extracts the CSRF token,
// interaction token, and the response body.
func profileGETFields(t *testing.T, h *Handler, profileCookie *http.Cookie, location string) (csrf, interactionToken, body string) {
	t.Helper()
	getReq := httptest.NewRequest(http.MethodGet, location, nil)
	getReq.AddCookie(profileCookie)
	getResp := httptest.NewRecorder()
	h.Profile(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("profile GET status=%d body=%q", getResp.Code, getResp.Body.String())
	}
	body = getResp.Body.String()
	csrfMatch := fedCMCSRFPattern.FindStringSubmatch(body)
	if len(csrfMatch) < 2 {
		t.Fatalf("could not extract CSRF token from profile form: %s", body)
	}
	interactionMatch := interactionPattern.FindStringSubmatch(body)
	if len(interactionMatch) < 2 {
		t.Fatalf("could not extract interaction from profile form: %s", body)
	}
	return csrfMatch[1], interactionMatch[1], body
}

// profilePOST builds and sends a POST /auth/profile request.
func profilePOST(t *testing.T, h *Handler, profileCookie *http.Cookie, interactionToken, csrf string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	resp := httptest.NewRecorder()
	h.Profile(resp, postReq)
	return resp
}

func TestProfilePOSTWrongCSRFReturns403(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	_, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	form := url.Values{
		"csrf_token":  {"bad-csrf-value-aaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"interaction": {interactionToken},
		"given_name":  {"Alice"},
	}
	resp := profilePOST(t, h, profileCookie, interactionToken, "bad-csrf-value-aaaaaaaaaaaaaaaaaaaaaaaaaa", form)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF should be 403, got %d body=%q", resp.Code, resp.Body.String())
	}
}

func TestProfilePOSTDuplicateBodyFieldReturns400(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	// Build raw body with duplicate given_name values
	body := "csrf_token=" + url.QueryEscape(csrf) +
		"&interaction=" + url.QueryEscape(interactionToken) +
		"&given_name=Alice&given_name=Bob"
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(body))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	resp := httptest.NewRecorder()
	h.Profile(resp, postReq)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("duplicate body field should be 400, got %d body=%q", resp.Code, resp.Body.String())
	}
}

func TestProfilePOSTOversizedBodyReturns400(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	// formLimit is 8<<10 = 8192; build a body exceeding that
	bigValue := strings.Repeat("x", 9000)
	body := "csrf_token=" + url.QueryEscape(csrf) +
		"&interaction=" + url.QueryEscape(interactionToken) +
		"&given_name=" + url.QueryEscape(bigValue)
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(body))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	resp := httptest.NewRecorder()
	h.Profile(resp, postReq)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("oversized body should be 400, got %d body=%q", resp.Code, resp.Body.String())
	}
}

func TestProfilePOSTDuplicateQueryInteractionReturns400(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	form := url.Values{
		"csrf_token":  {csrf},
		"interaction": {interactionToken},
		"given_name":  {"Alice"},
	}
	// Duplicate interaction in query string: len(r.URL.Query()) != 1
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken+"&interaction=dup", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	resp := httptest.NewRecorder()
	h.Profile(resp, postReq)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("duplicate query interaction should be 400, got %d body=%q", resp.Code, resp.Body.String())
	}
}

func TestProfilePOSTFromOtherAuthenticatedSessionDenied(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	_, itok, _ := profileGETFields(t, h, profileCookie, location)

	// Create a second authenticated session via browser store directly
	issued, err := h.browser.CreateSession(context.Background(), "user-1", "pwd", time.Now().Add(time.Hour), "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	otherCookie, err := browser.SessionCookie(h.issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	// Second session has no matching interaction → denied
	form := url.Values{
		"csrf_token":  {"any-value"},
		"interaction": {itok},
		"given_name":  {"Mallory"},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+itok, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(otherCookie)
	resp := httptest.NewRecorder()
	h.Profile(resp, postReq)
	if resp.Code == http.StatusSeeOther || resp.Code == http.StatusFound {
		t.Fatalf("other session POST should not succeed: status=%d", resp.Code)
	}
}

func TestProfilePOSTValidRetryAfterRejectedStillCompletes(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	// First attempt with disallowed extra field → rejected (400)
	badBody := "csrf_token=" + url.QueryEscape(csrf) +
		"&interaction=" + url.QueryEscape(interactionToken) +
		"&given_name=Alice&evil_field=bad"
	badReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(badBody))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.Header.Set("Sec-Fetch-Site", "same-origin")
	badReq.AddCookie(profileCookie)
	badResp := httptest.NewRecorder()
	h.Profile(badResp, badReq)
	if badResp.Code != http.StatusBadRequest {
		t.Fatalf("first bad POST should be 400, got %d", badResp.Code)
	}

	// Valid retry with same interaction → should still succeed
	form := url.Values{
		"csrf_token":  {csrf},
		"interaction": {interactionToken},
		"given_name":  {"Alice"},
	}
	goodResp := profilePOST(t, h, profileCookie, interactionToken, csrf, form)
	if goodResp.Code != http.StatusSeeOther {
		t.Fatalf("valid retry should be 303, got %d body=%q", goodResp.Code, goodResp.Body.String())
	}
	if !strings.Contains(goodResp.Header().Get("Location"), "code=") {
		t.Fatalf("expected code redirect after valid retry, got %q", goodResp.Header().Get("Location"))
	}
}

func TestProfilePOSTPromptNoneIncompleteProfileYieldsInteractionRequired(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "profile-recovery-email", SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('user-1','alice@example.test')`}); err != nil {
		t.Fatal(err)
	}
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.SetUserValuesPolicy(policy, h.identity.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	// Create an authenticated session for alice
	cookie := authenticatedCookie(t, h)

	// prompt=none with incomplete profile → should get interaction_required error, not profile UI
	values := authorizeValues()
	values.Set("prompt", "none")
	req := httptest.NewRequest(http.MethodGet, authorizePath+"?"+values.Encode(), nil)
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	h.Authorize(resp, req)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d body=%q", resp.Code, resp.Body.String())
	}
	location, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad redirect location: %v", err)
	}
	if location.Query().Get("error") != "interaction_required" {
		t.Fatalf("expected interaction_required error, got %q", location.Query().Get("error"))
	}
}

func TestProfileMaxAgeZeroFreshLoginPreservesSessionAndCompletes(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "profile-recovery-email", SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('user-1','alice@example.test')`}); err != nil {
		t.Fatal(err)
	}
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.SetUserValuesPolicy(policy, h.identity.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	// Authorize with max_age=0 → forces re-authentication
	values := authorizeValues()
	values.Set("max_age", "0")
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+values.Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	// Login → should redirect to profile (incomplete profile)
	loginResp := httptest.NewRecorder()
	h.Login(loginResp, postLogin(init, interaction, "alice", "correct password"))
	if loginResp.Code != http.StatusSeeOther && loginResp.Code != http.StatusFound {
		t.Fatalf("login status=%d", loginResp.Code)
	}
	profileCookie := loginResp.Result().Cookies()[0]
	location := loginResp.Header().Get("Location")
	if !strings.HasPrefix(location, "/auth/profile?interaction=") {
		t.Fatalf("expected profile redirect, got %q", location)
	}

	// Record session before profile submission
	sessionBefore, err := h.browser.LoadSession(context.Background(), profileCookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	// GET profile form and POST
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)
	form := url.Values{"csrf_token": {csrf}, "interaction": {interactionToken}, "given_name": {"Alice"}}
	postResp := profilePOST(t, h, profileCookie, interactionToken, csrf, form)
	if postResp.Code != http.StatusSeeOther {
		t.Fatalf("profile POST status=%d body=%q", postResp.Code, postResp.Body.String())
	}
	postLocation := postResp.Header().Get("Location")
	if !strings.Contains(postLocation, "code=") {
		t.Fatalf("expected code redirect, got %q", postLocation)
	}

	// Verify session CreatedAt preserved
	sessionAfter, err := h.browser.LoadSession(context.Background(), profileCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionBefore.CreatedAt.Equal(sessionAfter.CreatedAt) {
		t.Fatalf("session CreatedAt changed: before=%s after=%s", sessionBefore.CreatedAt, sessionAfter.CreatedAt)
	}
	if sessionBefore.ID != sessionAfter.ID {
		t.Fatalf("session ID changed: before=%s after=%s", sessionBefore.ID, sessionAfter.ID)
	}
}

func TestProfileConcurrentPOSTExactlyOneCodeCallback(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	form := url.Values{
		"csrf_token":  {csrf},
		"interaction": {interactionToken},
		"given_name":  {"Alice"},
	}

	const concurrency = 4
	results := make(chan int, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			resp := profilePOST(t, h, profileCookie, interactionToken, csrf, form)
			results <- resp.Code
		}()
	}

	seeOtherCount := 0
	for i := 0; i < concurrency; i++ {
		code := <-results
		if code == http.StatusSeeOther {
			seeOtherCount++
		}
	}
	if seeOtherCount != 1 {
		t.Fatalf("expected exactly 1 successful code callback, got %d", seeOtherCount)
	}
}

func TestProfileConcurrentReplayIssuesNoAdditionalCode(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	form := url.Values{
		"csrf_token":  {csrf},
		"interaction": {interactionToken},
		"given_name":  {"Alice"},
	}

	// First POST succeeds
	first := profilePOST(t, h, profileCookie, interactionToken, csrf, form)
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first POST status=%d", first.Code)
	}
	firstCode := first.Header().Get("Location")

	// Replay with same body → should not issue another code
	replay := profilePOST(t, h, profileCookie, interactionToken, csrf, form)
	if replay.Code == http.StatusSeeOther || replay.Code == http.StatusFound {
		replayLoc := replay.Header().Get("Location")
		if replayLoc != "" && replayLoc != firstCode {
			t.Fatalf("replay issued a new code: first=%q replay=%q", firstCode, replayLoc)
		}
		t.Fatalf("replay should not succeed: status=%d", replay.Code)
	}
}

func TestProfileDisabledWhenRevalidateDuringLoginFalse(t *testing.T) {
	h, _, profileCookie, location := profileSetup(t)

	// Get valid CSRF and interaction tokens while policy is still enabled
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	// Disable policy (RevalidateDuringLogin=false)
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: false, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}

	// GET should deny with 503
	getReq := httptest.NewRequest(http.MethodGet, location, nil)
	getReq.AddCookie(profileCookie)
	getResp := httptest.NewRecorder()
	h.Profile(getResp, getReq)
	if getResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled policy GET should be 503, got %d body=%q", getResp.Code, getResp.Body.String())
	}

	// POST should deny with 503
	form := url.Values{
		"csrf_token":  {csrf},
		"interaction": {interactionToken},
		"given_name":  {"Alice"},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/auth/profile?interaction="+interactionToken, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.AddCookie(profileCookie)
	postResp := httptest.NewRecorder()
	h.Profile(postResp, postReq)
	if postResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled policy POST should be 503, got %d body=%q", postResp.Code, postResp.Body.String())
	}

	// Verify profile unchanged (no given_name set)
	claims, err := h.identity.ProfileClaimsBySubject(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.GivenName != nil {
		t.Fatalf("profile should be unchanged, got given_name=%q", *claims.GivenName)
	}

	// Verify interaction still pending (not consumed)
	_, err = h.browser.LoadAuthorizationInteractionReadOnlyForSession(context.Background(), profileCookie.Value, interactionToken)
	if err != nil {
		t.Fatalf("interaction should still be pending: %v", err)
	}
}

func TestProfileMaxAgeZeroDeterministicDelayPreservesSession(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "profile-recovery-email", SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('user-1','alice@example.test')`}); err != nil {
		t.Fatal(err)
	}
	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	if err := h.SetUserValuesPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.SetUserValuesPolicy(policy, h.identity.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	// Authorize with max_age=0 → forces re-authentication
	values := authorizeValues()
	values.Set("max_age", "0")
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+values.Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	// Login → should redirect to profile (incomplete profile)
	loginResp := httptest.NewRecorder()
	h.Login(loginResp, postLogin(init, interaction, "alice", "correct password"))
	if loginResp.Code != http.StatusSeeOther && loginResp.Code != http.StatusFound {
		t.Fatalf("login status=%d", loginResp.Code)
	}
	profileCookie := loginResp.Result().Cookies()[0]
	location := loginResp.Header().Get("Location")
	if !strings.HasPrefix(location, "/auth/profile?interaction=") {
		t.Fatalf("expected profile redirect, got %q", location)
	}

	// Record session before profile submission
	sessionBefore, err := h.browser.LoadSession(context.Background(), profileCookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	// GET profile form
	csrf, interactionToken, _ := profileGETFields(t, h, profileCookie, location)

	// Advance h.now by 2s immediately before POST to prove max_age=0 doesn't reject
	originalNow := h.now
	advanced := sessionBefore.CreatedAt.Add(2 * time.Second)
	h.now = func() time.Time { return advanced }
	defer func() { h.now = originalNow }()

	form := url.Values{"csrf_token": {csrf}, "interaction": {interactionToken}, "given_name": {"Alice"}}
	postResp := profilePOST(t, h, profileCookie, interactionToken, csrf, form)
	if postResp.Code != http.StatusSeeOther {
		t.Fatalf("profile POST status=%d body=%q", postResp.Code, postResp.Body.String())
	}
	postLocation := postResp.Header().Get("Location")
	if !strings.Contains(postLocation, "code=") {
		t.Fatalf("expected code redirect, got %q", postLocation)
	}

	// Verify session CreatedAt preserved
	sessionAfter, err := h.browser.LoadSession(context.Background(), profileCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionBefore.CreatedAt.Equal(sessionAfter.CreatedAt) {
		t.Fatalf("session CreatedAt changed: before=%s after=%s", sessionBefore.CreatedAt, sessionAfter.CreatedAt)
	}
	if sessionBefore.ID != sessionAfter.ID {
		t.Fatalf("session ID changed: before=%s after=%s", sessionBefore.ID, sessionAfter.ID)
	}
}

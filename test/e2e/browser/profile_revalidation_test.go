package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestProfileRevalidationPrepareLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROFILE_REVALIDATION") != "1" {
		t.Skip("set GOAUTHY_E2E_PROFILE_REVALIDATION=1 to run profile revalidation E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, adminCookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "profile-revalidation-admin")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	email := "profile-revalidation@goauthy.e2e"
	created := do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewBufferString(`{"email":"`+email+`","language":"en","roles":[]}`), adminHeaders)
	var user struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&user)
	created.Body.Close()
	if created.StatusCode != http.StatusOK || err != nil || user.ID == "" {
		t.Fatalf("create status=%d err=%v", created.StatusCode, err)
	}
	profile := map[string]any{"email": email, "given_name": "Existing", "family_name": "User", "roles": []string{}, "enabled": true, "email_verified": true, "password": "Profile-Revalidation-1A", "user_values": map[string]any{}}
	body, _ := json.Marshal(profile)
	updated := do(t, client, http.MethodPut, primary+"/auth/v1/users/"+user.ID, bytes.NewReader(body), adminHeaders)
	updated.Body.Close()
	if updated.StatusCode != http.StatusOK {
		t.Fatalf("activate status=%d", updated.StatusCode)
	}
}

func TestProfileRevalidationCompleteLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_PROFILE_REVALIDATION") != "1" {
		t.Skip("set GOAUTHY_E2E_PROFILE_REVALIDATION=1 to run profile revalidation E2E")
	}
	primary, secondary, _, _, clientSecret := browserE2EConfig(t)
	email := "profile-revalidation@goauthy.e2e"
	password := "Profile-Revalidation-1A"
	state := "profile-revalidation-state"
	nonce := "profile-revalidation-nonce"

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	challenge := pkceChallenge(verifier)
	authorizeURL := oidcAuthorizationURLForClient(t, primary, "goauthy-dev", defaultRedirectURI, challenge, state, nonce, "openid profile address offline_access")

	response := do(t, client, http.MethodGet, authorizeURL, nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("authorize status=%d want 200", response.StatusCode)
	}
	interaction := loginInteraction(t, response)
	initCookie := assertSessionCookie(t, response.Cookies(), primary)
	response.Body.Close()

	form := url.Values{"interaction": {interaction}, "username": {email}, "password": {password}}
	response = do(t, client, http.MethodPost, secondary+"/auth/login", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Sec-Fetch-Site": "same-origin",
	})
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		response.Body.Close()
		t.Fatalf("login status=%d want 302/303", response.StatusCode)
	}
	location := response.Header.Get("Location")
	authCookie := assertSessionCookie(t, response.Cookies(), primary)
	if authCookie.Value == initCookie.Value {
		response.Body.Close()
		t.Fatal("login did not rotate the browser session")
	}
	response.Body.Close()

	if !strings.Contains(location, "/auth/profile?interaction=") {
		t.Fatalf("expected profile redirect, got %q", location)
	}
	profileInteraction := strings.TrimPrefix(location, "/auth/profile?interaction=")
	if profileInteraction == "" {
		t.Fatal("profile redirect has no interaction token")
	}

	profileClient := clientWithCookie(t, primary, authCookie)
	response = do(t, profileClient, http.MethodGet, primary+"/auth/profile?interaction="+url.QueryEscape(profileInteraction), nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("profile GET status=%d want 200", response.StatusCode)
	}
	profileBody := readLimitedBody(t, response)
	response.Body.Close()

	profileCSRF, ok := hiddenInputValue(profileBody, "csrf_token")
	if !ok || profileCSRF == "" {
		t.Fatal("profile form has no csrf_token")
	}
	formInteraction, ok := hiddenInputValue(profileBody, "interaction")
	if !ok || formInteraction == "" {
		t.Fatal("profile form has no interaction")
	}
	if !strings.Contains(profileBody, `name="city"`) {
		t.Fatal("profile form has no city input")
	}

	profileForm := url.Values{
		"interaction": {formInteraction},
		"csrf_token":  {"wrong-csrf-token"},
		"given_name":  {"Existing"},
		"family_name": {"User"},
		"city":        {"Seoul"},
		"zip":         {"03000"},
	}
	response = do(t, profileClient, http.MethodPost, primary+"/auth/profile?interaction="+url.QueryEscape(profileInteraction), strings.NewReader(profileForm.Encode()), map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Sec-Fetch-Site": "same-origin",
	})
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong CSRF status=%d want 403", response.StatusCode)
	}

	profileForm.Set("csrf_token", profileCSRF)
	response = do(t, profileClient, http.MethodPost, primary+"/auth/profile?interaction="+url.QueryEscape(profileInteraction), strings.NewReader(profileForm.Encode()), map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Sec-Fetch-Site": "same-origin",
	})
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		response.Body.Close()
		t.Fatalf("valid profile POST status=%d want 302/303", response.StatusCode)
	}
	postCookies := response.Cookies()
	for _, c := range postCookies {
		if c.Name == authCookie.Name {
			t.Fatal("profile completion must not rotate the browser session")
		}
	}
	codeLocation := response.Header.Get("Location")
	response.Body.Close()
	callback, err := url.Parse(codeLocation)
	if err != nil || callback.Query().Get("state") != state || callback.Query().Get("error") != "" || callback.Query().Get("code") == "" {
		t.Fatalf("profile completion redirect is not a valid callback: %q", codeLocation)
	}
	code := callback.Query().Get("code")

	tokens := exchangeCode(t, profileClient, primary, clientSecret, defaultRedirectURI, code, verifier)
	keys := publicJWKS(t, profileClient, primary)
	claims := verifyPublicIDToken(t, tokens.IDToken, keys, primary)
	if claims.Profile.Address == nil {
		t.Fatal("ID token has no address claim")
	}
	if claims.Profile.Address["locality"] != "Seoul" {
		t.Fatalf("ID token address locality=%q want Seoul", claims.Profile.Address["locality"])
	}
	if claims.AuthTime.IsZero() {
		t.Fatal("ID token has no auth_time")
	}

	replayForm := url.Values{
		"interaction": {formInteraction},
		"csrf_token":  {profileCSRF},
		"given_name":  {"Existing"},
		"family_name": {"User"},
		"city":        {"Seoul"},
		"zip":         {"03000"},
	}
	response = do(t, profileClient, http.MethodPost, primary+"/auth/profile?interaction="+url.QueryEscape(profileInteraction), strings.NewReader(replayForm.Encode()), map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Sec-Fetch-Site": "same-origin",
	})
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed profile POST status=%d want 403/400", response.StatusCode)
	}
}

package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestPasswordLifecycleAcrossPods(t *testing.T) {
	primary, secondary, tertiary, username, password, subject := passwordLifecycleConfig(t)
	switch os.Getenv("GOAUTHY_E2E_PASSWORD_LIFECYCLE_PHASE") {
	case "before-restart":
		testPasswordLifecycleBeforeRestart(t, primary, secondary, tertiary, username, password, subject)
	case "after-restart":
		testPasswordLifecycleAfterRestart(t, primary, tertiary, username)
	default:
		t.Skip("set GOAUTHY_E2E_PASSWORD_LIFECYCLE_PHASE to run the password lifecycle E2E")
	}
}

func testPasswordLifecycleBeforeRestart(t *testing.T, primary, secondary, tertiary, username, password, subject string) {
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	if code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "password-lifecycle-initial", "password-lifecycle-initial-nonce"), primary, primary, username, password, "password-lifecycle-initial"); code == "" {
		t.Fatal("initial password login returned no authorization code")
	}

	const first = "Correct-Horse-Browser-Staple-1"
	const second = "Correct-Horse-Browser-Staple-2"
	changePassword(t, client, primary, secondary, subject, password, first, http.StatusOK)
	assertPasswordLogin(t, primary, tertiary, username, "initial", password, http.StatusUnauthorized)
	assertPasswordLogin(t, primary, tertiary, username, "first", first, http.StatusFound)

	changePassword(t, client, primary, secondary, subject, first, second, http.StatusOK)
	changePassword(t, client, primary, secondary, subject, second, first, http.StatusBadRequest)
	assertPasswordLogin(t, primary, tertiary, username, "second", second, http.StatusFound)
}

func testPasswordLifecycleAfterRestart(t *testing.T, primary, tertiary, username string) {
	assertPasswordLogin(t, primary, tertiary, username, "initial", "correct-horse-browser-staple", http.StatusUnauthorized)
	assertPasswordLogin(t, primary, tertiary, username, "first", "Correct-Horse-Browser-Staple-1", http.StatusUnauthorized)
	assertPasswordLogin(t, primary, tertiary, username, "second", "Correct-Horse-Browser-Staple-2", http.StatusFound)
}

func passwordLifecycleConfig(t *testing.T) (primary, secondary, tertiary, username, password, subject string) {
	t.Helper()
	primary, secondary, username, password, _ = browserE2EConfig(t)
	tertiary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	subject = os.Getenv("GOAUTHY_E2E_BROWSER_SUBJECT")
	if tertiary == "" || subject == "" {
		t.Skip("set GOAUTHY_E2E_TERTIARY_URL and GOAUTHY_E2E_BROWSER_SUBJECT to run password lifecycle E2E")
	}
	return primary, secondary, tertiary, username, password, subject
}

func changePassword(t *testing.T, client *http.Client, csrfBase, targetBase, subject, current, next string, want int) {
	t.Helper()
	response := do(t, client, http.MethodGet, csrfBase+"/account/password", nil, nil)
	var page struct {
		CSRFToken      string          `json:"csrf_token"`
		PasswordPolicy json.RawMessage `json:"password_policy"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&page)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || page.CSRFToken == "" || len(page.PasswordPolicy) == 0 {
		t.Fatalf("password page status=%d csrf=%t policy=%s err=%v", response.StatusCode, page.CSRFToken != "", page.PasswordPolicy, err)
	}

	body, err := json.Marshal(struct {
		Current string `json:"password_current"`
		Next    string `json:"password_new"`
	}{Current: current, Next: next})
	if err != nil {
		t.Fatal(err)
	}
	response = do(t, client, http.MethodPut, targetBase+"/auth/v1/users/"+url.PathEscape(subject)+"/self", strings.NewReader(string(body)), map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   page.CSRFToken,
	})
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("password change status=%d, want %d", response.StatusCode, want)
	}
}

func assertPasswordLogin(t *testing.T, authorizeBase, loginBase, username, label, password string, want int) {
	t.Helper()
	assertPasswordLoginWithClient(t, newBrowserClient(t), authorizeBase, loginBase, username, label, password, want)
}

func assertPasswordLoginWithClient(t *testing.T, client *http.Client, authorizeBase, loginBase, username, label, password string, want int) {
	t.Helper()
	verifier := pkceVerifier(t)
	response, _ := passwordLoginResponse(t, client, oidcAuthorizationURL(t, authorizeBase, defaultRedirectURI, pkceChallenge(verifier), "password-lifecycle-login-"+label, "password-lifecycle-login-nonce"), authorizeBase, loginBase, username, password)
	defer response.Body.Close()
	if want == http.StatusFound && response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		t.Fatalf("password login %s status=%d, want authorization redirect", label, response.StatusCode)
	}
	if want != http.StatusFound && response.StatusCode != want {
		t.Fatalf("password login %s status=%d, want %d", label, response.StatusCode, want)
	}
	if want == http.StatusFound {
		callback, err := url.Parse(response.Header.Get("Location"))
		if err != nil || callback.Query().Get("code") == "" {
			t.Fatalf("password login did not return an authorization code: %q", response.Header.Get("Location"))
		}
	}
}

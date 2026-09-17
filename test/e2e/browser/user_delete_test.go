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
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

const (
	userDeleteSelfEmail  = "user-delete-self@goauthy.e2e"
	userDeleteAdminEmail = "user-delete-admin@goauthy.e2e"
	userDeleteSelfPass   = "User-Delete-Self-1A"
	userDeleteAdminPass  = "User-Delete-Admin-1A"
)

func TestUserDeletionAcrossPods(t *testing.T) {
	primary, secondary, username, password, _ := browserE2EConfig(t)
	switch os.Getenv("GOAUTHY_E2E_USER_DELETE_PHASE") {
	case "before-replacement":
		sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
		if sinkURL == "" {
			t.Skip("set GOAUTHY_E2E_SMTP_SINK_URL to run user-deletion E2E")
		}
		testUserDeletionBeforeReplacement(t, primary, secondary, username, password, sinkURL)
	case "after-replacement":
		testUserDeletionAfterReplacement(t, primary, secondary, username, password)
	default:
		t.Skip("set GOAUTHY_E2E_USER_DELETE_PHASE to run user-deletion E2E")
	}
}

func testUserDeletionBeforeReplacement(t *testing.T, primary, secondary, adminUsername, adminPassword, sinkURL string) {
	mailbox := &http.Client{Timeout: 5 * time.Second}
	clearSMTPMailbox(t, mailbox, sinkURL)
	selfSubject := registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, userDeleteSelfEmail, userDeleteSelfPass, "user_delete_self")
	adminSubject := registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, userDeleteAdminEmail, userDeleteAdminPass, "user_delete_admin")

	selfClient := newBrowserClient(t)
	_, selfCookie := loginForAuthorizationURL(t, selfClient, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "user-delete-self-login", "user-delete-self-nonce"), primary, secondary, userDeleteSelfEmail, userDeleteSelfPass, "user-delete-self-login")
	selfCSRF, err := browsersession.DeriveCSRFToken(selfCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, selfClient, http.MethodGet, primary+"/auth/v1/users/"+url.PathEscape(selfSubject)+"/self/delete", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("self-delete capability status=%d", response.StatusCode)
	}
	response = do(t, selfClient, http.MethodDelete, secondary+"/auth/v1/users/"+url.PathEscape(selfSubject)+"/self/delete", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": selfCSRF})
	deletedCookies := response.Cookies()
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("cross-pod self-delete status=%d", response.StatusCode)
	}
	assertDeletedSessionCookie(t, deletedCookies, secondary)

	assertUserDeleteSessionRejected(t, primary, selfCookie, "user-delete-old-self-session")
	assertPasswordLogin(t, primary, secondary, userDeleteSelfEmail, "user-delete-relogin", userDeleteSelfPass, http.StatusUnauthorized)

	adminTargetClient := newBrowserClient(t)
	_, adminTargetCookie := loginForAuthorizationURL(t, adminTargetClient, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "user-delete-admin-target-login", "user-delete-admin-target-nonce"), primary, secondary, userDeleteAdminEmail, userDeleteAdminPass, "user-delete-admin-target-login")

	adminClient := newBrowserClient(t)
	_, adminCookie := loginForAuthorizationURL(t, adminClient, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "user-delete-admin-login", "user-delete-admin-nonce"), primary, secondary, adminUsername, adminPassword, "user-delete-admin-login")
	adminCSRF, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	deleteEndpoint := secondary + "/auth/v1/users/" + url.PathEscape(adminSubject)
	response = do(t, adminClient, http.MethodDelete, deleteEndpoint, nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": adminCSRF})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("cross-pod admin delete status=%d", response.StatusCode)
	}
	assertUserDeleteSessionRejected(t, primary, adminTargetCookie, "user-delete-old-admin-target-session")
	assertPasswordLogin(t, primary, secondary, userDeleteAdminEmail, "user-delete-admin-target-relogin", userDeleteAdminPass, http.StatusUnauthorized)
	response = do(t, adminClient, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(adminSubject), nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": adminCSRF})
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("admin delete replay status=%d", response.StatusCode)
	}

	response = do(t, adminClient, http.MethodDelete, secondary+"/auth/v1/users/bootstrap-admin", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": adminCSRF})
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("final bootstrap-admin delete status=%d", response.StatusCode)
	}
	assertPasswordLogin(t, primary, secondary, adminUsername, "user-delete-bootstrap-survives", adminPassword, http.StatusFound)
}

func testUserDeletionAfterReplacement(t *testing.T, primary, secondary, adminUsername, adminPassword string) {
	for _, user := range []struct {
		email    string
		password string
		label    string
	}{
		{userDeleteSelfEmail, userDeleteSelfPass, "user-delete-self-after-replacement"},
		{userDeleteAdminEmail, userDeleteAdminPass, "user-delete-admin-after-replacement"},
	} {
		assertPasswordLogin(t, primary, secondary, user.email, user.label+"-forward", user.password, http.StatusUnauthorized)
		assertPasswordLogin(t, secondary, primary, user.email, user.label+"-reverse", user.password, http.StatusUnauthorized)
	}
	assertPasswordLogin(t, primary, secondary, adminUsername, "user-delete-bootstrap-after-replacement", adminPassword, http.StatusFound)
}

func assertUserDeleteSessionRejected(t *testing.T, baseURL string, cookie *http.Cookie, state string) {
	t.Helper()
	client := clientWithCookie(t, baseURL, cookie)
	response := do(t, client, http.MethodGet, oidcAuthorizationURL(t, baseURL, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), state, state+"-nonce"), nil, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("deleted old-session authorize status=%d", response.StatusCode)
	}
	if loginInteraction(t, response) == "" {
		t.Fatal("deleted old session was still authenticated")
	}
}

func registerUserDeleteUser(t *testing.T, mailbox *http.Client, primary, secondary, sinkURL, email, password, username string) string {
	t.Helper()
	proof := solvePasswordResetPoW(t, passwordResetPoWChallenge(t, mailbox, primary), 10)
	body, err := json.Marshal(map[string]string{
		"email": email, "preferred_username": username, "given_name": "User", "family_name": "Delete", "pow": proof, "redirect_uri": defaultRedirectURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, mailbox, http.MethodPost, primary+"/auth/v1/users/register", bytes.NewReader(body), map[string]string{"Content-Type": "application/json"})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("register %s status=%d", email, response.StatusCode)
	}
	mail := waitForResetMail(t, mailbox, sinkURL, email)
	activationURL, err := url.Parse(mail.resetURL)
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(strings.Trim(activationURL.EscapedPath(), "/"), "/")
	if len(segments) != 6 || segments[0] != "auth" || segments[1] != "v1" || segments[2] != "users" || segments[4] != "reset" || segments[5] == "" {
		t.Fatalf("invalid activation URL path=%q", activationURL.EscapedPath())
	}
	subject, err := url.PathUnescape(segments[3])
	if err != nil || subject == "" {
		t.Fatalf("invalid activation subject=%q err=%v", segments[3], err)
	}
	activation := newBrowserClient(t)
	response = do(t, activation, http.MethodGet, mail.resetURL, nil, nil)
	var challenge struct {
		CSRFToken string `json:"csrf_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 4<<10)).Decode(&challenge)
	cookies := response.Cookies()
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || challenge.CSRFToken == "" || len(cookies) != 1 {
		t.Fatalf("activation GET status=%d csrf=%t cookies=%d decode=%v", response.StatusCode, challenge.CSRFToken != "", len(cookies), err)
	}
	secondaryURL, err := url.Parse(secondary)
	if err != nil {
		t.Fatal(err)
	}
	activation.Jar.SetCookies(secondaryURL, cookies)
	activationBody, err := json.Marshal(map[string]string{"magic_link_id": segments[5], "password": password})
	if err != nil {
		t.Fatal(err)
	}
	response = do(t, activation, http.MethodPut, secondary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(activationBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": challenge.CSRFToken,
	})
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("activation PUT status=%d", response.StatusCode)
	}
	return subject
}

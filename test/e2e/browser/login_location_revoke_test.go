package browser

import (
	"encoding/json"
	"io"
	"net/http"
	stdmail "net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var loginLocationRevokeURLPattern = regexp.MustCompile(`https?://[^\s<>"]+/auth/v1/users/[^/\s<>"]+/revoke/[A-Za-z0-9]{48}\?ip=[^\s<>"]+`)

func TestLoginLocationRevokeLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGIN_LOCATION") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGIN_LOCATION=1 to run login-location revoke E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	adminUsername := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	adminPassword := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if primary == "" || secondary == "" || adminUsername == "" || adminPassword == "" || sinkURL == "" {
		t.Fatal("GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, GOAUTHY_E2E_BROWSER_USERNAME, GOAUTHY_E2E_BROWSER_PASSWORD, and GOAUTHY_E2E_SMTP_SINK_URL are required")
	}

	mailbox := newBrowserClient(t)
	email := "login-location-revoke-" + randomManagedUIID(t) + "@goauthy.e2e"
	password := "Login-Location-Revoke-1A"
	preferredUsername := "login_location_revoke_" + randomManagedUIID(t)
	subject := registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, email, password, preferredUsername)
	defer func() {
		cleanup := newBrowserClient(t)
		_, adminCookie := loginForAuthorizationURL(t, cleanup, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "login-location-revoke-cleanup", "login-location-revoke-cleanup-nonce"), primary, secondary, adminUsername, adminPassword, "login-location-revoke-cleanup")
		csrf, err := csrfFromCookie(adminCookie)
		if err != nil {
			t.Errorf("cleanup CSRF: %v", err)
			return
		}
		response := do(t, cleanup, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(subject), nil, map[string]string{
			"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf,
		})
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
			t.Errorf("cleanup delete status=%d", response.StatusCode)
		}
	}()

	clearSMTPMailbox(t, mailbox, sinkURL)
	userClient := newBrowserClient(t)
	_, sessionCookie := loginForAuthorizationURL(t, userClient, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "login-location-revoke-login", "login-location-revoke-login-nonce"), primary, secondary, email, password, "login-location-revoke-login")
	mail := waitForLoginLocationMail(t, mailbox, sinkURL, email)
	if count := smtpMessageCount(t, mailbox, sinkURL); count != 1 {
		t.Fatalf("post-login SMTP message count=%d, want 1", count)
	}
	revokeURL, code, revokeIP := extractLoginLocationRevokeURL(t, mail.plain, subject, primary)
	if !strings.Contains(mail.plain, "IP: "+revokeIP) || !strings.Contains(mail.html, "IP: <b>"+revokeIP+"</b>") {
		t.Fatal("login-location email did not contain the revoke IP in both MIME bodies")
	}

	revokeClient := newBrowserClient(t)
	first := do(t, revokeClient, http.MethodGet, revokeURL, nil, nil)
	firstBody := readGenericLoginRevokeHTML(t, first, "successful revoke")
	if !strings.Contains(firstBody, "All Logins and Sessions have been revoked") || strings.Contains(firstBody, code) {
		t.Fatal("successful revoke response was not generic HTML")
	}

	checked := make(map[string]bool, 3)
	for _, base := range []string{primary, secondary, strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")} {
		if base != "" && !checked[base] {
			checked[base] = true
			assertUserDeleteSessionRejected(t, base, sessionCookie, "login-location-revoke-old-session")
		}
	}

	replay := do(t, newBrowserClient(t), http.MethodGet, revokeURL, nil, nil)
	replayBody := readGenericLoginRevokeHTML(t, replay, "replayed revoke")
	if !strings.Contains(replayBody, "Code not found") || strings.Contains(replayBody, code) {
		t.Fatal("replayed revoke response was not generic HTML")
	}
}

func waitForLoginLocationMail(t *testing.T, client *http.Client, sinkURL, recipient string) resetMail {
	t.Helper()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := client.Get(sinkURL + "/messages")
		if err == nil {
			var mailbox struct {
				Messages []smtpSinkMessage `json:"messages"`
			}
			err = readJSONResponse(response, &mailbox)
			if err == nil && response.StatusCode == http.StatusOK {
				for _, message := range mailbox.Messages {
					if strings.EqualFold(strings.Join(message.To, ","), recipient) {
						if parsed, ok := loginLocationMailFromSMTP(message.Data); ok {
							return parsed
						}
					}
				}
			}
		} else if response != nil {
			response.Body.Close()
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-timer.C:
			t.Fatal("timed out waiting for login-location SMTP message")
		case <-ticker.C:
		}
	}
}

func loginLocationMailFromSMTP(raw string) (resetMail, bool) {
	message, err := stdmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return resetMail{}, false
	}
	mail := resetMail{}
	if err := collectResetMailParts(message.Header, message.Body, &mail, 0); err != nil {
		return resetMail{}, false
	}
	return mail, mail.plain != "" && mail.html != ""
}

func extractLoginLocationRevokeURL(t *testing.T, plain, subject, issuer string) (string, string, string) {
	t.Helper()
	match := loginLocationRevokeURLPattern.FindString(plain)
	if match == "" {
		t.Fatal("login-location email did not contain a revoke URL")
	}
	parsed, err := url.Parse(match)
	if err != nil {
		t.Fatal("login-location revoke URL was not parseable")
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != issuerURL.Scheme || parsed.Host != issuerURL.Host {
		t.Fatal("login-location revoke URL issuer did not match the deployment")
	}
	path := parsed.EscapedPath()
	marker := "/auth/v1/users/"
	index := strings.LastIndex(path, marker)
	if index < 0 {
		t.Fatal("login-location revoke URL path was invalid")
	}
	parts := strings.Split(strings.Trim(path[index+len(marker):], "/"), "/")
	if len(parts) != 3 || parts[1] != "revoke" {
		t.Fatal("login-location revoke URL path was invalid")
	}
	decodedSubject, err := url.PathUnescape(parts[0])
	if err != nil || decodedSubject != subject || len(parts[2]) != 48 {
		t.Fatal("login-location revoke URL identity or code was invalid")
	}
	values, ok := parsed.Query()["ip"]
	if !ok || len(values) != 1 || values[0] == "" {
		t.Fatal("login-location revoke URL IP query was invalid")
	}
	return match, parts[2], values[0]
}

func readGenericLoginRevokeHTML(t *testing.T, response *http.Response, operation string) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") || !strings.Contains(string(body), "<!doctype html>") {
		t.Fatalf("%s response was not generic HTML status=%d content-type=%q read=%v", operation, response.StatusCode, response.Header.Get("Content-Type"), err)
	}
	return string(body)
}

func readJSONResponse(response *http.Response, target any) error {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return io.ErrUnexpectedEOF
	}
	return json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(target)
}

func TestLoginLocationRevokeURLExtraction(t *testing.T) {
	subject := "user-registration"
	code := strings.Repeat("a", 48)
	link := "http://localhost:59510/auth/v1/users/" + subject + "/revoke/" + code + "?ip=192.0.2.1"
	got, gotCode, ip := extractLoginLocationRevokeURL(t, "Revoke: "+link+"\nAccount: http://localhost:59510/auth/v1/account", subject, "http://localhost:59510")
	if got != link || gotCode != code || ip != "192.0.2.1" {
		t.Fatal("revoke URL extraction failed")
	}
}

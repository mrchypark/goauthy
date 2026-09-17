package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	stdmail "net/mail"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	passwordNewTemplateSubject = "GoAuthy E2E 비밀번호 설정"
	passwordNewTemplateCopy    = "이 메일은 GoAuthy E2E 한국어 공개 등록 템플릿으로 전송되었습니다."
	registeredAlreadySubject   = "GoAuthy E2E 이미 등록된 사용자"
	registeredAlreadyCopy      = "이 이메일은 이미 GoAuthy E2E에 등록되어 있습니다."
)

func TestOpenRegistrationAcrossPods(t *testing.T) {
	primary, secondary, _, _, _ := browserE2EConfig(t)
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if sinkURL == "" {
		t.Skip("set GOAUTHY_E2E_SMTP_SINK_URL to run open-registration E2E")
	}
	mailbox := &http.Client{Timeout: 5 * time.Second}
	clearSMTPMailbox(t, mailbox, sinkURL)

	request := func(email, proof string) []byte {
		t.Helper()
		body, err := json.Marshal(struct {
			Email             string `json:"email"`
			PreferredUsername string `json:"preferred_username"`
			GivenName         string `json:"given_name"`
			FamilyName        string `json:"family_name"`
			Proof             string `json:"pow"`
			RedirectURI       string `json:"redirect_uri"`
		}{email, "open_registration", "Open", "Registration", proof, defaultRedirectURI})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	postLocale := func(baseURL string, body []byte, language string) *http.Response {
		return do(t, mailbox, http.MethodPost, baseURL+"/auth/v1/users/register", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Accept-Language": language})
	}
	post := func(baseURL string, body []byte) *http.Response {
		return postLocale(baseURL, body, "ko-KR,ko;q=0.9,en;q=0.1")
	}

	response := post(primary, request("outside@example.test", "not-consumed"))
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("domain-rejected registration status=%d", response.StatusCode)
	}
	if count := smtpMessageCount(t, mailbox, sinkURL); count != 0 {
		t.Fatalf("domain-rejected registration sent %d messages", count)
	}

	response = post(primary, request("open@goauthy.e2e", "invalid"))
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid proof registration status=%d", response.StatusCode)
	}

	proof := solvePasswordResetPoW(t, passwordResetPoWChallenge(t, mailbox, primary), 10)
	missingGivenName := map[string]any{"email": "open@goauthy.e2e", "preferred_username": "open_registration", "family_name": "Registration", "pow": proof, "redirect_uri": defaultRedirectURI}
	missingBody, err := json.Marshal(missingGivenName)
	if err != nil {
		t.Fatal(err)
	}
	response = post(primary, missingBody)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing given_name registration status=%d", response.StatusCode)
	}
	if count := smtpMessageCount(t, mailbox, sinkURL); count != 0 {
		t.Fatalf("rejected missing given_name sent %d messages", count)
	}
	response = post(primary, request("open@goauthy.e2e", proof))
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || len(body) != 0 || response.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("valid registration status=%d body=%q cors=%q", response.StatusCode, body, response.Header.Get("Access-Control-Allow-Origin"))
	}

	response = post(secondary, request("open@goauthy.e2e", proof))
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed proof registration status=%d", response.StatusCode)
	}

	mail := waitForResetMail(t, mailbox, sinkURL, "open@goauthy.e2e")
	if mail.subject != passwordNewTemplateSubject {
		t.Fatalf("password-new email subject=%q", mail.subject)
	}
	for kind, body := range map[string]string{"plain": mail.plain, "html": mail.html} {
		if !strings.Contains(body, passwordNewTemplateCopy) || !strings.Contains(body, mail.resetURL) {
			t.Fatalf("password-new %s body lacks configured copy or activation URL", kind)
		}
	}
	activationURL, err := url.Parse(mail.resetURL)
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(strings.Trim(activationURL.EscapedPath(), "/"), "/")
	if len(segments) != 6 || segments[0] != "auth" || segments[1] != "v1" || segments[2] != "users" || segments[4] != "reset" || segments[5] == "" {
		t.Fatalf("invalid password-new URL path=%q", activationURL.EscapedPath())
	}
	subject, err := url.PathUnescape(segments[3])
	if err != nil || subject == "" {
		t.Fatalf("invalid password-new URL subject=%q err=%v", segments[3], err)
	}

	assertPasswordLogin(t, primary, secondary, "open@goauthy.e2e", "pending", "Open-Registration-Password-1A", http.StatusUnauthorized)

	activationClient := newBrowserClient(t)
	response = do(t, activationClient, http.MethodGet, mail.resetURL, nil, nil)
	var challenge struct {
		CSRFToken string `json:"csrf_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 4<<10)).Decode(&challenge)
	cookies := response.Cookies()
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || challenge.CSRFToken == "" || len(cookies) != 1 {
		t.Fatalf("password-new GET status=%d csrf=%t cookies=%d decode=%v", response.StatusCode, challenge.CSRFToken != "", len(cookies), err)
	}
	secondaryURL, err := url.Parse(secondary)
	if err != nil {
		t.Fatal(err)
	}
	activationClient.Jar.SetCookies(secondaryURL, cookies)
	const password = "Open-Registration-Password-1A"
	putBody, err := json.Marshal(struct {
		MagicLinkID string `json:"magic_link_id"`
		Password    string `json:"password"`
	}{segments[5], password})
	if err != nil {
		t.Fatal(err)
	}
	response = do(t, activationClient, http.MethodPut, secondary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(putBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": challenge.CSRFToken,
	})
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted || response.Header.Get("Location") != defaultRedirectURI {
		t.Fatalf("cross-pod password-new status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}

	replayClient := clientWithCookie(t, primary, cookies[0])
	response = do(t, replayClient, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(putBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": challenge.CSRFToken,
	})
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("password-new replay status=%d", response.StatusCode)
	}
	assertPasswordLogin(t, primary, secondary, "open@goauthy.e2e", "activated", password, http.StatusFound)

	// The locale is persisted on the identity, so a later authenticated detail
	// read must remain Korean even though the duplicate request below asks for English.
	detailClient := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, _ = loginForCode(t, detailClient, primary, secondary, defaultRedirectURI, pkceChallenge(verifier), "open@goauthy.e2e", password, "open-registration-language")
	nodes := []string{primary, secondary}
	if tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/"); tertiary != "" {
		nodes = append(nodes, tertiary)
	}
	for _, baseURL := range nodes {
		response = do(t, detailClient, http.MethodGet, baseURL+"/auth/v1/users/"+url.PathEscape(subject), nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
		var detail struct {
			Language string `json:"language"`
			ID       string `json:"id"`
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&detail)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil || detail.ID != subject || detail.Language != "ko" {
			t.Fatalf("authenticated user detail base=%s status=%d id=%q language=%q decode=%v", baseURL, response.StatusCode, detail.ID, detail.Language, err)
		}
	}

	duplicateProof := solvePasswordResetPoW(t, passwordResetPoWChallenge(t, mailbox, secondary), 10)
	response = postLocale(secondary, request("open@goauthy.e2e", duplicateProof), "en-US,en;q=0.9")
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("duplicate registration status=%d body=%q", response.StatusCode, body)
	}
	registered := waitForRegisteredAlreadyMail(t, mailbox, sinkURL, "open@goauthy.e2e")
	if registered.subject != registeredAlreadySubject || !strings.Contains(registered.plain, registeredAlreadyCopy) || !strings.Contains(registered.html, registeredAlreadyCopy) {
		t.Fatalf("registered-already email subject=%q plain=%q html=%q", registered.subject, registered.plain, registered.html)
	}
	if passwordResetURL.MatchString(registered.plain) || passwordResetURL.MatchString(registered.html) {
		t.Fatal("registered-already email must not contain an activation bearer URL")
	}
	if count := smtpMessageCount(t, mailbox, sinkURL); count != 2 {
		t.Fatalf("duplicate registration mail count=%d, want 2", count)
	}
}

func smtpMessageCount(t *testing.T, client *http.Client, sinkURL string) int {
	t.Helper()
	response := do(t, client, http.MethodGet, sinkURL+"/messages", nil, nil)
	defer response.Body.Close()
	var mailbox struct {
		Messages []smtpSinkMessage `json:"messages"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&mailbox)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("SMTP mailbox status=%d decode=%v", response.StatusCode, err)
	}
	return len(mailbox.Messages)
}

func waitForRegisteredAlreadyMail(t *testing.T, client *http.Client, sinkURL, recipient string) resetMail {
	t.Helper()
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		response, err := client.Get(sinkURL + "/messages")
		if err == nil {
			var mailbox struct {
				Messages []smtpSinkMessage `json:"messages"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&mailbox)
			response.Body.Close()
			if err == nil && response.StatusCode == http.StatusOK {
				for _, message := range mailbox.Messages {
					if !strings.EqualFold(strings.Join(message.To, ","), recipient) {
						continue
					}
					mail, ok := registeredAlreadyMailFromSMTP(message.Data)
					if ok {
						return mail
					}
				}
			}
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-timeout.C:
			t.Fatal("timed out waiting for registered-already SMTP message")
		case <-poll.C:
		}
	}
}

func registeredAlreadyMailFromSMTP(raw string) (resetMail, bool) {
	message, err := stdmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return resetMail{}, false
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != registeredAlreadySubject {
		return resetMail{}, false
	}
	mail := resetMail{subject: subject}
	if err := collectResetMailParts(message.Header, message.Body, &mail, 0); err != nil {
		return resetMail{}, false
	}
	return mail, mail.plain != "" && mail.html != ""
}

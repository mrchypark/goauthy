package browser

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	stdmail "net/mail"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

var passwordResetURL = regexp.MustCompile(`https?://[^\s<>"\r\n]+/auth/v1/users/[^/\s]+/reset/[A-Za-z0-9_-]+`)

const (
	passwordResetTemplateSubject = "GoAuthy E2E 비밀번호 초기화"
	passwordResetTemplateCopy    = "이 메일은 GoAuthy E2E 한국어 템플릿으로 전송되었습니다."
)

func TestPasswordResetAcrossPods(t *testing.T) {
	primary, secondary, username, password, _ := browserE2EConfig(t)
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	subject := os.Getenv("GOAUTHY_E2E_BROWSER_SUBJECT")
	email := os.Getenv("GOAUTHY_E2E_BROWSER_EMAIL")
	if sinkURL == "" || subject == "" || email == "" {
		t.Skip("set GOAUTHY_E2E_SMTP_SINK_URL, GOAUTHY_E2E_BROWSER_SUBJECT, and GOAUTHY_E2E_BROWSER_EMAIL to run password-reset E2E")
	}

	mailboxClient := &http.Client{Timeout: 5 * time.Second}
	clearSMTPMailbox(t, mailboxClient, sinkURL)

	sessionClient := newBrowserClient(t)
	_, sessionCookie := loginForCode(t, sessionClient, primary, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "password-reset-before")
	csrf, _ := browsersession.DeriveCSRFToken(sessionCookie.Value)
	nodes := []string{primary, secondary}
	if tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/"); tertiary != "" {
		nodes = append(nodes, tertiary)
	}
	eventsKey := createAdminAPIKey(t, sessionClient, primary, csrf, "password-reset-events", []apiKeyAccess{{Group: "Events", AccessRights: []string{"read"}}})
	cleanupClient, cleanupCSRF := sessionClient, csrf
	defer func() {
		apiKeyStatus(t, cleanupClient, http.MethodDelete, primary+"/auth/v1/api_keys/password-reset-events", nil, rbacMutationHeaders(cleanupCSRF), http.StatusOK, "password reset events key cleanup")
	}()
	baselineEvents := passwordResetEvents(t, nodes, eventsKey, email)

	powChallenge := passwordResetPoWChallenge(t, mailboxClient, primary)
	requestBody, err := json.Marshal(struct {
		Email string `json:"email"`
		PoW   string `json:"pow"`
	}{Email: email, PoW: powChallenge + "invalid"})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, mailboxClient, http.MethodPost, primary+"/auth/v1/users/request_reset", bytes.NewReader(requestBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin",
	})
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid proof request-reset status=%d", response.StatusCode)
	}

	proof := solvePasswordResetPoW(t, powChallenge, 10)
	requestBody, err = json.Marshal(struct {
		Email string `json:"email"`
		PoW   string `json:"pow"`
	}{Email: email, PoW: proof})
	if err != nil {
		t.Fatal(err)
	}
	response = do(t, mailboxClient, http.MethodPost, primary+"/auth/v1/users/request_reset", bytes.NewReader(requestBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin",
	})
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("request-reset status=%d", response.StatusCode)
	}
	assertPasswordResetEventsUnchanged(t, nodes, eventsKey, email, baselineEvents)
	response = do(t, mailboxClient, http.MethodPost, secondary+"/auth/v1/users/request_reset", bytes.NewReader(requestBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin",
	})
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed proof request-reset status=%d", response.StatusCode)
	}
	assertPasswordResetEventsUnchanged(t, nodes, eventsKey, email, baselineEvents)

	resetMail := waitForResetMail(t, mailboxClient, sinkURL, email)
	if resetMail.subject != passwordResetTemplateSubject {
		t.Fatalf("password-reset email subject = %q", resetMail.subject)
	}
	for kind, body := range map[string]string{"plain": resetMail.plain, "html": resetMail.html} {
		if !strings.Contains(body, passwordResetTemplateCopy) || !strings.Contains(body, resetMail.resetURL) {
			t.Fatalf("password-reset %s body does not contain configured copy and reset URL", kind)
		}
	}
	resetURL := resetMail.resetURL
	reset, err := url.Parse(resetURL)
	if err != nil {
		t.Fatal("SMTP message contains an invalid reset URL")
	}
	segments := strings.Split(strings.Trim(reset.EscapedPath(), "/"), "/")
	if len(segments) != 6 || segments[0] != "auth" || segments[1] != "v1" || segments[2] != "users" || segments[4] != "reset" {
		t.Fatal("SMTP message contains an invalid reset URL path")
	}
	linkSubject, err := url.PathUnescape(segments[3])
	if err != nil || linkSubject != subject || segments[5] == "" {
		t.Fatal("SMTP message reset URL does not match the configured subject")
	}

	resetClient := newBrowserClient(t)
	response = do(t, resetClient, http.MethodGet, resetURL, nil, nil)
	var resetChallenge struct {
		CSRFToken string `json:"csrf_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 4<<10)).Decode(&resetChallenge)
	resetCookies := response.Cookies()
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || resetChallenge.CSRFToken == "" || len(resetCookies) != 1 {
		t.Fatalf("reset GET status=%d csrf=%t cookies=%d decode=%v", response.StatusCode, resetChallenge.CSRFToken != "", len(resetCookies), err)
	}
	resetTarget, err := url.Parse(secondary)
	if err != nil {
		t.Fatal(err)
	}
	resetClient.Jar.SetCookies(resetTarget, resetCookies)

	const nextPassword = "Reset-Password-1A"
	resetBody, err := json.Marshal(struct {
		MagicLinkID string `json:"magic_link_id"`
		Password    string `json:"password"`
	}{MagicLinkID: segments[5], Password: nextPassword})
	if err != nil {
		t.Fatal(err)
	}
	response = do(t, resetClient, http.MethodPut, secondary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(resetBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": resetChallenge.CSRFToken,
	})
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("cross-pod reset status=%d", response.StatusCode)
	}
	resetEvents := passwordResetEvents(t, nodes, eventsKey, email)
	var resetEventID string
	for _, base := range nodes {
		before := baselineEvents[base]
		after := resetEvents[base]
		if len(after) != len(before)+1 {
			t.Fatalf("reset event delta node=%s before=%d after=%d", base, len(before), len(after))
		}
		for id := range after {
			if _, ok := before[id]; ok {
				continue
			}
			if resetEventID == "" {
				resetEventID = id
			} else if resetEventID != id {
				t.Fatalf("reset event ID differs node=%s", base)
			}
		}
	}
	cleanupClient = newBrowserClient(t)
	_, cleanupCookie := loginForCode(t, cleanupClient, primary, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, nextPassword, "password-reset-cleanup")
	cleanupCSRF, _ = browsersession.DeriveCSRFToken(cleanupCookie.Value)

	replayClient := clientWithCookie(t, primary, resetCookies[0])
	response = do(t, replayClient, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(resetBody), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": resetChallenge.CSRFToken,
	})
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("reset replay status=%d", response.StatusCode)
	}
	assertPasswordResetEventsUnchanged(t, nodes, eventsKey, email, resetEvents)

	response = do(t, clientWithCookie(t, secondary, sessionCookie), http.MethodGet, oidcAuthorizationURL(t, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "password-reset-revoked", "password-reset-revoked-nonce"), nil, nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("revoked browser session status=%d", response.StatusCode)
	}
	if interaction := loginInteraction(t, response); interaction == "" {
		response.Body.Close()
		t.Fatal("revoked browser session did not require login")
	}
	response.Body.Close()

	assertPasswordLogin(t, primary, secondary, username, "password-reset-old", password, http.StatusUnauthorized)
	assertPasswordLogin(t, primary, secondary, username, "password-reset-new", nextPassword, http.StatusFound)
}

func passwordResetPoWChallenge(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	response := do(t, client, http.MethodPost, baseURL+"/auth/v1/pow", nil, nil)
	body, err := io.ReadAll(io.LimitReader(response.Body, 512))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("password-reset PoW challenge status=%d content_type=%q read=%v", response.StatusCode, response.Header.Get("Content-Type"), err)
	}
	challenge := string(body)
	parts := strings.Split(challenge, ":")
	if len(parts) != 6 || parts[0] != "1" || parts[1] != "10" || parts[5] != "" || len(parts[3]) != 16 || len(parts[4]) != 43 {
		t.Fatal("password-reset PoW challenge has an invalid format")
	}
	if _, err := strconv.ParseInt(parts[2], 10, 64); err != nil {
		t.Fatal("password-reset PoW challenge has an invalid expiry")
	}
	if salt, err := base64.RawStdEncoding.DecodeString(parts[3]); err != nil || len(salt) != 12 {
		t.Fatal("password-reset PoW challenge has an invalid salt")
	}
	if digest, err := base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(digest) != sha256.Size {
		t.Fatal("password-reset PoW challenge has an invalid digest")
	}
	return challenge
}

func solvePasswordResetPoW(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for counter := uint64(0); counter < 1<<20; counter++ {
		proof := challenge + strconv.FormatUint(counter, 10)
		if hasLeadingZeroBits(sha256.Sum256([]byte(proof)), difficulty) {
			return proof
		}
	}
	t.Fatal("password-reset PoW solver exceeded its counter bound")
	return ""
}

func hasLeadingZeroBits(sum [sha256.Size]byte, bits int) bool {
	for _, value := range sum {
		if bits <= 0 {
			return true
		}
		if value != 0 {
			return bits < 8 && value>>(8-bits) == 0
		}
		bits -= 8
	}
	return bits <= 0
}

func passwordResetEvents(t *testing.T, bases []string, secret, email string) map[string]map[string]struct{} {
	t.Helper()
	out := make(map[string]map[string]struct{}, len(bases))
	for _, base := range bases {
		body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info","typ":"UserPasswordReset"}`))
		response := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
		var events []eventlog.Event
		err := json.NewDecoder(response.Body).Decode(&events)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("password reset events node=%s status=%d decode=%v", base, response.StatusCode, err)
		}
		ids := make(map[string]struct{}, len(events))
		for _, event := range events {
			if event.Text == nil || *event.Text != "Reset via Password Reset Form: "+email {
				continue
			}
			if event.Type != eventlog.UserPasswordReset || event.Level != eventlog.Notice || event.Text == nil || *event.Text != "Reset via Password Reset Form: "+email || event.Data != nil || event.Timestamp <= 0 || event.IP == nil {
				t.Fatalf("invalid password reset event node=%s event=%+v", base, event)
			}
			if _, err := netip.ParseAddr(*event.IP); err != nil {
				t.Fatalf("invalid password reset event IP node=%s ip=%q", base, *event.IP)
			}
			ids[event.ID] = struct{}{}
		}
		out[base] = ids
	}
	return out
}

func assertPasswordResetEventsUnchanged(t *testing.T, bases []string, secret, email string, before map[string]map[string]struct{}) {
	t.Helper()
	after := passwordResetEvents(t, bases, secret, email)
	for _, base := range bases {
		if len(after[base]) != len(before[base]) {
			t.Fatalf("password reset events changed node=%s before=%d after=%d", base, len(before[base]), len(after[base]))
		}
		for id := range before[base] {
			if _, ok := after[base][id]; !ok {
				t.Fatalf("password reset event disappeared node=%s", base)
			}
		}
	}
}

type smtpSinkMessage struct {
	To   []string `json:"to"`
	Data string   `json:"data"`
}

func clearSMTPMailbox(t *testing.T, client *http.Client, sinkURL string) {
	t.Helper()
	response := do(t, client, http.MethodDelete, sinkURL+"/messages", nil, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("SMTP mailbox reset status=%d", response.StatusCode)
	}
}

type resetMail struct {
	subject  string
	plain    string
	html     string
	resetURL string
}

func waitForResetMail(t *testing.T, client *http.Client, sinkURL, recipient string) resetMail {
	t.Helper()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	var lastStatus, messageCount int
	for {
		response, err := client.Get(sinkURL + "/messages")
		lastErr = err
		if err == nil {
			var mailbox struct {
				Messages []smtpSinkMessage `json:"messages"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&mailbox)
			lastErr, lastStatus, messageCount = err, response.StatusCode, len(mailbox.Messages)
			response.Body.Close()
			if err == nil && lastStatus == http.StatusOK {
				for _, message := range mailbox.Messages {
					if strings.EqualFold(strings.Join(message.To, ","), recipient) {
						if message, ok := resetMailFromSMTP(message.Data); ok {
							return message
						}
					}
				}
			}
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-timer.C:
			t.Fatalf("timed out waiting for password-reset SMTP message recipient=%q last_status=%d messages=%d last_error=%v", recipient, lastStatus, messageCount, lastErr)
		case <-ticker.C:
		}
	}
}

func resetMailFromSMTP(raw string) (resetMail, bool) {
	message, err := stdmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return resetMail{}, false
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil {
		return resetMail{}, false
	}
	mail := resetMail{subject: subject}
	if err := collectResetMailParts(message.Header, message.Body, &mail, 0); err != nil {
		return resetMail{}, false
	}
	mail.resetURL = passwordResetURL.FindString(mail.plain)
	if mail.resetURL == "" {
		mail.resetURL = passwordResetURL.FindString(mail.html)
	}
	return mail, mail.resetURL != "" && mail.plain != "" && mail.html != ""
}

func collectResetMailParts(header stdmail.Header, body io.Reader, mail *resetMail, depth int) error {
	if depth > 4 {
		return io.ErrUnexpectedEOF
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return io.ErrUnexpectedEOF
		}
		reader := multipart.NewReader(body, boundary)
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if err := collectResetMailParts(stdmail.Header(part.Header), part, mail, depth+1); err != nil {
				part.Close()
				return err
			}
			part.Close()
		}
	}
	body = decodedMIMEBody(header, body)
	data, err := io.ReadAll(io.LimitReader(body, 64<<10))
	if err != nil {
		return err
	}
	switch strings.ToLower(mediaType) {
	case "text/plain":
		mail.plain += string(data)
	case "text/html":
		mail.html += string(data)
	}
	return nil
}

func decodedMIMEBody(header stdmail.Header, body io.Reader) io.Reader {
	switch strings.ToLower(header.Get("Content-Transfer-Encoding")) {
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, body)
	default:
		return body
	}
}

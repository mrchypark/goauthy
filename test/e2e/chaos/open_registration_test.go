// Package chaos exercises failure recovery through independently forwarded pods.
package chaos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/http"
	stdmail "net/mail"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var pendingPasswordURL = regexp.MustCompile(`https?://[^\s<>"\r\n]+/auth/v1/users/[^/\s]+/reset/[A-Za-z0-9_-]+`)

// TestOpenRegistrationPendingPasswordSurvivesPodReplacement verifies the
// replicated token state, rather than timing: create on one pod, replace that
// pod, then race two remaining pods to consume the same bearer. Exactly one
// write may commit.
func TestOpenRegistrationPendingPasswordSurvivesPodReplacement(t *testing.T) {
	primary, secondary, tertiary := chaosURLs(t)
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	email := os.Getenv("GOAUTHY_E2E_OPEN_REG_EMAIL")
	contextName := os.Getenv("GOAUTHY_E2E_CHAOS_CONTEXT")
	pod := os.Getenv("GOAUTHY_E2E_CHAOS_DELETE_POD")
	if sinkURL == "" || email == "" || contextName == "" || pod == "" {
		t.Skip("set SMTP sink, open-registration email, and chaos kubectl context/pod to run open-registration chaos E2E")
	}
	namespace := os.Getenv("GOAUTHY_E2E_CHAOS_NAMESPACE")
	if namespace == "" {
		namespace = "goauthy"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	clearMailbox(t, client, sinkURL)
	proof := solvePoW(t, issuePoW(t, client, primary))
	payload, err := json.Marshal(map[string]string{"email": email, "given_name": "Pending", "pow": proof})
	if err != nil {
		t.Fatal(err)
	}
	response := chaosRequest(t, client, http.MethodPost, primary+"/auth/v1/users/register", bytes.NewReader(payload), map[string]string{"Content-Type": "application/json", "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.1"})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("open registration status=%d", response.StatusCode)
	}
	link := waitForPendingPasswordLink(t, client, sinkURL, email)

	// kubectl's ready condition is the synchronization oracle; there is no
	// sleep-based grace period after deleting the issuing pod.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	kubectl(t, ctx, "--context", contextName, "-n", namespace, "delete", "pod", pod, "--wait=true")
	kubectl(t, ctx, "--context", contextName, "-n", namespace, "wait", "--for=condition=Ready", "pod/"+pod, "--timeout=180s")

	resetURL, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(strings.Trim(resetURL.EscapedPath(), "/"), "/")
	if len(segments) != 6 || segments[0] != "auth" || segments[1] != "v1" || segments[2] != "users" || segments[4] != "reset" || segments[3] == "" || segments[5] == "" {
		t.Fatalf("pending-password link path=%q", resetURL.EscapedPath())
	}
	subject, err := url.PathUnescape(segments[3])
	if err != nil {
		t.Fatal(err)
	}

	// The issuing pod was deliberately deleted. Preserve the exact bearer path
	// from the mail while sending it to a surviving independently forwarded pod.
	challenge := chaosRequest(t, client, http.MethodGet, secondary+resetURL.RequestURI(), nil, nil)
	var document struct {
		CSRFToken string `json:"csrf_token"`
	}
	err = json.NewDecoder(io.LimitReader(challenge.Body, 4<<10)).Decode(&document)
	cookies := challenge.Cookies()
	challenge.Body.Close()
	if challenge.StatusCode != http.StatusOK || err != nil || document.CSRFToken == "" || len(cookies) != 1 {
		t.Fatalf("pending-password GET status=%d csrf=%t cookies=%d decode=%v", challenge.StatusCode, document.CSRFToken != "", len(cookies), err)
	}

	body, err := json.Marshal(map[string]string{"magic_link_id": segments[5], "password": "ActivatedPassword2"})
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(chan int, 2)
	var group sync.WaitGroup
	for _, baseURL := range []string{secondary, tertiary} {
		group.Add(1)
		go func(baseURL string) {
			defer group.Done()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, baseURL+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(body))
			if err != nil {
				statuses <- 0
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			request.Header.Set("X-Pwd-CSRF-Token", document.CSRFToken)
			request.AddCookie(cookies[0])
			response, err := client.Do(request)
			if err != nil {
				statuses <- 0
				return
			}
			response.Body.Close()
			statuses <- response.StatusCode
		}(baseURL)
	}
	group.Wait()
	close(statuses)
	accepted, rejected := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusAccepted:
			accepted++
		case http.StatusBadRequest:
			rejected++
		default:
			t.Fatalf("pending-password concurrent consumption status=%d", status)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("pending-password consumption accepted=%d rejected=%d, want exactly one commit", accepted, rejected)
	}

	// A third state read/write must observe the committed consumption, not a
	// pod-local cache. This is a deterministic final-state assertion.
	response = chaosRequest(t, client, http.MethodPut, secondary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(body), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": document.CSRFToken, "Cookie": cookies[0].Name + "=" + cookies[0].Value,
	})
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("pending-password final replay status=%d", response.StatusCode)
	}
	// SMTP completion is synchronous with registration. After pod replacement,
	// a contradictory request locale must still render the stored preference.
	clearMailbox(t, client, sinkURL)
	proof = solvePoW(t, issuePoW(t, client, secondary))
	payload, err = json.Marshal(map[string]string{"email": email, "given_name": "Pending", "pow": proof})
	if err != nil {
		t.Fatal(err)
	}
	response = chaosRequest(t, client, http.MethodPost, secondary+"/auth/v1/users/register", bytes.NewReader(payload), map[string]string{"Content-Type": "application/json", "Accept-Language": "en"})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("post-replacement duplicate=%d", response.StatusCode)
	}
	response = chaosRequest(t, client, http.MethodGet, sinkURL+"/messages", nil, nil)
	var mailbox struct {
		Messages []struct {
			To   []string `json:"to"`
			Data string   `json:"data"`
		} `json:"messages"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&mailbox)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || len(mailbox.Messages) != 1 {
		t.Fatalf("post-replacement mail status=%d count=%d err=%v", response.StatusCode, len(mailbox.Messages), err)
	}
	message := mailbox.Messages[0]
	if len(message.To) != 1 || message.To[0] != email || !smtpHasTemplate(message.Data, "GoAuthy E2E 이미 등록된 사용자", "이 이메일은 이미 GoAuthy E2E에 등록되어 있습니다.") || pendingPasswordURL.MatchString(message.Data) {
		t.Fatal("post-replacement duplicate did not preserve language or included activation bearer")
	}
}

func chaosURLs(t *testing.T) (string, string, string) {
	t.Helper()
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if primary == "" || secondary == "" || tertiary == "" {
		t.Skip("set three independently forwarded GOAUTHY_E2E URLs to run open-registration chaos E2E")
	}
	return primary, secondary, tertiary
}

func kubectl(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	output, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s: %v: %s", strings.Join(args, " "), err, output)
	}
}

func issuePoW(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	response := chaosRequest(t, client, http.MethodPost, baseURL+"/auth/v1/pow", nil, nil)
	data, err := io.ReadAll(io.LimitReader(response.Body, 512))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("PoW status=%d read=%v", response.StatusCode, err)
	}
	parts := strings.Split(string(data), ":")
	if len(parts) != 6 || parts[0] != "1" || parts[5] != "" {
		t.Fatalf("invalid PoW challenge %q", data)
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		t.Fatalf("invalid PoW difficulty: %v", err)
	}
	return string(data)
}

func solvePoW(t *testing.T, challenge string) string {
	t.Helper()
	parts := strings.Split(challenge, ":")
	difficulty, _ := strconv.Atoi(parts[1])
	for counter := uint64(0); counter < 1<<20; counter++ {
		proof := challenge + strconv.FormatUint(counter, 10)
		if leadingZeros(sha256.Sum256([]byte(proof)), difficulty) {
			return proof
		}
	}
	t.Fatal("PoW solver exceeded fixed counter bound")
	return ""
}

func leadingZeros(sum [sha256.Size]byte, bits int) bool {
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

func clearMailbox(t *testing.T, client *http.Client, sinkURL string) {
	t.Helper()
	response := chaosRequest(t, client, http.MethodDelete, sinkURL+"/messages", nil, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("SMTP mailbox reset status=%d", response.StatusCode)
	}
}

func waitForPendingPasswordLink(t *testing.T, client *http.Client, sinkURL, recipient string) string {
	t.Helper()
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		response, err := client.Get(sinkURL + "/messages")
		if err == nil {
			var mailbox struct {
				Messages []struct {
					To   []string `json:"to"`
					Data string   `json:"data"`
				} `json:"messages"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&mailbox)
			response.Body.Close()
			if err == nil && response.StatusCode == http.StatusOK {
				for _, message := range mailbox.Messages {
					if strings.EqualFold(strings.Join(message.To, ","), recipient) {
						if link := pendingPasswordURL.FindString(strings.ReplaceAll(message.Data, "=\r\n", "")); link != "" {
							if !smtpHasTemplate(message.Data, "GoAuthy E2E 비밀번호 설정", "이 메일은 GoAuthy E2E 한국어 공개 등록 템플릿으로 전송되었습니다.") {
								t.Fatalf("pending-password SMTP message lacks selected Korean template copy")
							}
							return link
						}
					}
				}
			}
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-timeout.C:
			t.Fatal("timed out waiting for pending-password SMTP link")
		case <-poll.C:
		}
	}
}

func smtpHasTemplate(raw, wantSubject, copy string) bool {
	message, err := stdmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return false
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != wantSubject {
		return false
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(raw)))
	return err == nil && strings.Contains(string(decoded), copy)
}

func chaosRequest(t *testing.T, client *http.Client, method, endpoint string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

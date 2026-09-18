package browser

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestEventNotificationsAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_EVENT_NOTIFICATIONS") != "1" {
		t.Skip("set GOAUTHY_E2E_EVENT_NOTIFICATIONS=1 to run event notification E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	sink := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	recipient := os.Getenv("GOAUTHY_EVENT_EMAIL_TO")
	if recipient == "" {
		recipient = "events@goauthy.e2e"
	}
	if primary == "" || secondary == "" || tertiary == "" || username == "" || password == "" || sink == "" {
		t.Fatal("peer URLs, browser username/password, and GOAUTHY_E2E_SMTP_SINK_URL are required")
	}
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "event-notifications")
	csrf, err := csrfFromNotificationCookie(cookie)
	if err != nil {
		t.Fatal(err)
	}
	mailbox := &http.Client{Timeout: 5 * time.Second}
	clearSMTPMailbox(t, mailbox, sink)
	for _, node := range []string{primary, secondary, tertiary} {
		before := notificationTestEventIDs(t, client, node)
		response := do(t, client, http.MethodPost, node+"/auth/v1/events/test", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("test event node=%s status=%d", node, response.StatusCode)
		}
		eventID := waitForNewNotificationTestEvent(t, client, node, before)
		waitForNotificationMail(t, mailbox, sink, recipient, eventID)
	}
}

func csrfFromNotificationCookie(cookie *http.Cookie) (string, error) {
	if cookie == nil {
		return "", io.ErrUnexpectedEOF
	}
	return browsersession.DeriveCSRFToken(cookie.Value)
}

func notificationTestEventIDs(t *testing.T, client *http.Client, base string) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, event := range queryLifecycleEvents(t, client, base) {
		if event.Type == eventlog.Test {
			ids[event.ID] = struct{}{}
		}
	}
	return ids
}

func waitForNewNotificationTestEvent(t *testing.T, client *http.Client, base string, before map[string]struct{}) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, event := range queryLifecycleEvents(t, client, base) {
			if event.Type == eventlog.Test {
				if _, ok := before[event.ID]; !ok {
					return event.ID
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for test event node=%s", base)
		case <-ticker.C:
		}
	}
}

func waitForNotificationMail(t *testing.T, client *http.Client, sink, recipient, eventID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := client.Get(sink + "/messages")
		if err == nil {
			var mailbox struct {
				Messages []smtpSinkMessage `json:"messages"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&mailbox)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil {
				for _, message := range mailbox.Messages {
					if len(message.To) == 1 && strings.EqualFold(message.To[0], recipient) && strings.Contains(message.Data, eventID) {
						return
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for notification email recipient=%q event=%s", recipient, eventID)
		case <-ticker.C:
		}
	}
}

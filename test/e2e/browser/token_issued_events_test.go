package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestTokenIssuedEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_TOKEN_EVENTS") != "1" {
		t.Skip("enable token event E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	exchanger := createCrossClientExchanger(t, admin, primary, headers, "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange")
	t.Cleanup(func() { deleteCrossClientExchanger(t, admin, primary, headers, exchanger) })
	client := newBrowserClient(t)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}
	response := tokenResponseForClient(t, client, secondary, exchanger.ID, exchanger.Secret, form)
	var source crossClientTokenResponse
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&source)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || source.AccessToken == "" {
		t.Fatal("machine issuance failed")
	}
	crossClientExchange(t, client, secondary, exchanger, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {source.AccessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	response = tokenResponseForClient(t, client, secondary, exchanger.ID, "invalid-secret", form)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid client status=%d", response.StatusCode)
	}
	want := 1
	if os.Getenv("GOAUTHY_E2E_EXPECT_TOKEN_EVENTS") == "false" {
		want = 0
	}
	ids := map[string]string{}
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		events := queryLifecycleEvents(t, admin, node)
		for _, flow := range []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"} {
			text := exchanger.ID + " (" + flow + ") "
			count := 0
			for _, event := range events {
				if event.Type != eventlog.TokenIssued || event.Text == nil || *event.Text != text {
					continue
				}
				count++
				if event.Level != expectedTokenEventLevel(t) || event.IP != nil || event.Data != nil || event.Timestamp <= 0 {
					t.Fatal("invalid token event payload")
				}
				if prior := ids[flow]; prior != "" && prior != event.ID {
					t.Fatal("event ID differs across nodes")
				}
				ids[flow] = event.ID
			}
			if count != want {
				t.Fatalf("flow=%s events=%d want=%d", flow, count, want)
			}
		}
	}
	if path := os.Getenv("GOAUTHY_E2E_TOKEN_EVENT_FILE"); path != "" {
		data, err := json.Marshal(ids)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	waitTokenEventNotifications(t, ids)

}

func TestTokenIssuedEventsPersisted(t *testing.T) {
	path := os.Getenv("GOAUTHY_E2E_TOKEN_EVENT_FILE")
	if path == "" {
		t.Skip("set token event state file for restart verification")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ids map[string]string
	if err := json.Unmarshal(data, &ids); err != nil {
		t.Fatal(err)
	}
	want := 2
	if os.Getenv("GOAUTHY_E2E_EXPECT_TOKEN_EVENTS") == "false" {
		want = 0
	}
	if len(ids) != want {
		t.Fatalf("saved event count=%d want=%d", len(ids), want)
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	admin, _ := rbacAuthenticatedClient(t, primary, secondary, username, password)
	for _, node := range adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")) {
		events := queryLifecycleEvents(t, admin, node)
		for _, id := range ids {
			found := 0
			for _, event := range events {
				if event.ID == id && event.Type == eventlog.TokenIssued {
					found++
				}
			}
			if found != 1 {
				t.Fatalf("persisted event matches=%d", found)
			}
		}
	}
}

func expectedTokenEventLevel(t *testing.T) eventlog.Level {
	t.Helper()
	level := eventlog.Level(os.Getenv("GOAUTHY_E2E_EXPECT_TOKEN_EVENT_LEVEL"))
	if level == "" {
		level = eventlog.Info
	}
	if !level.Valid() {
		t.Fatal("invalid expected token event level")
	}
	return level
}

func waitTokenEventNotifications(t *testing.T, ids map[string]string) {
	t.Helper()
	if os.Getenv("GOAUTHY_E2E_EVENT_NOTIFICATIONS") != "1" {
		return
	}
	sink := os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL")
	recipient := os.Getenv("GOAUTHY_EVENT_EMAIL_TO")
	if recipient == "" {
		recipient = "events@goauthy.e2e"
	}
	mailbox := &http.Client{Timeout: 5 * time.Second}
	for _, id := range ids {
		if id == "" {
			t.Fatal("missing token event ID for notification")
		}
		waitForNotificationMail(t, mailbox, sink, recipient, id)
	}
}

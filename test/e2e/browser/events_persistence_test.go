package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

// TestCreationEventsPersisted is run after the standalone process is restarted
// with the same data and key directories. It deliberately authenticates again,
// then reads the lifecycle stream through the browser-admin authorization path.
func TestCreationEventsPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_EVENTS_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_EVENTS_PERSISTENCE=1 to run event persistence E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	clientSecret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || secondary == "" || username == "" || password == "" || clientSecret == "" {
		t.Fatal("GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, browser username/password, and client secret are required")
	}
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		tertiary = secondary
	}
	nodes := []string{primary, secondary, tertiary}
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, _ = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "events-persistence", "events-persistence-nonce"), primary, secondary, username, password, "events-persistence")

	adminIDs := assertAdminCreateEvents(t, client, nodes, "admin-created@goauthy.e2e")
	var ordinaryID string
	for _, base := range nodes {
		events := queryLifecycleEvents(t, client, base)
		var ordinary []eventlog.Event
		for _, event := range events {
			if event.Text != nil && *event.Text == "open@goauthy.e2e" {
				if event.Type != eventlog.NewUserRegistered || event.Level != eventlog.Info || event.Data != nil || event.Timestamp <= 0 {
					t.Fatalf("invalid ordinary registration event node=%s event=%+v", base, event)
				}
				ordinary = append(ordinary, event)
			}
		}
		if len(ordinary) != 1 {
			t.Fatalf("ordinary registration event count node=%s: %d", base, len(ordinary))
		}
		if ordinaryID == "" {
			ordinaryID = ordinary[0].ID
		} else if ordinaryID != ordinary[0].ID {
			t.Fatalf("ordinary event ID differs after restart node=%s", base)
		}
		streamEvents := collectStreamEvents(t, client, base, "latest=1000&level=info", func(events []eventlog.Event) bool {
			return hasEvent(events, "admin-created@goauthy.e2e", eventlog.NewUserRegistered) && hasEvent(events, "admin-created@goauthy.e2e", eventlog.NewRauthyAdmin) && hasEvent(events, "open@goauthy.e2e", eventlog.NewUserRegistered)
		})
		for typ, expectedID := range map[eventlog.Type]string{
			eventlog.NewUserRegistered: adminIDs[eventlog.NewUserRegistered],
			eventlog.NewRauthyAdmin:    adminIDs[eventlog.NewRauthyAdmin],
		} {
			matches := matchingEvents(streamEvents, "admin-created@goauthy.e2e", typ)
			if len(matches) != 1 || matches[0].ID != expectedID {
				t.Fatalf("persisted stream admin event node=%s type=%s events=%+v", base, typ, matches)
			}
		}
		matches := matchingEvents(streamEvents, "open@goauthy.e2e", eventlog.NewUserRegistered)
		if len(matches) != 1 || matches[0].ID != ordinaryID {
			t.Fatalf("persisted stream ordinary event node=%s events=%+v", base, matches)
		}
	}
}

func queryLifecycleEvents(t *testing.T, client *http.Client, base string) []eventlog.Event {
	t.Helper()
	request := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info"}`))
	response := do(t, client, http.MethodPost, base+"/auth/v1/events", request, map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin",
	})
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("events persistence node=%s status=%d read=%v", base, response.StatusCode, err)
	}
	var events []eventlog.Event
	if err := json.Unmarshal(body, &events); err != nil {
		t.Fatalf("events persistence node=%s decode=%v", base, err)
	}
	return events
}

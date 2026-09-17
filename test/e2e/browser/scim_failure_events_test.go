package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

type scimFailureEventState struct {
	Subject string         `json:"subject"`
	Event   eventlog.Event `json:"event"`
}

func TestSCIMFailureEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SCIM_FAILURE_EVENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_SCIM_FAILURE_EVENTS=1 to run SCIM failure-event E2E")
	}
	primary, secondary, tertiary, fixtureAdmin, username, password, statePath := scimFailureConfig(t)
	nodes := []string{primary, secondary, tertiary}
	fixture := &http.Client{Timeout: 5 * time.Second}
	assertSCIMBootstrapProjection(t, fixture, fixtureAdmin)
	setSCIMFixtureMode(t, fixture, fixtureAdmin, "temporary")

	client := newBrowserClient(t)
	_, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-failure-event", "scim-failure-event-nonce"), primary, secondary, username, password, "scim-failure-event")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	email := "scim-failure-event@goauthy.e2e"
	body, err := json.Marshal(map[string]any{"email": email, "language": "en", "roles": []string{}, "preferred_username": "scim-failure-event", "tz": "UTC", "user_expires": 4102444800})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || readErr != nil {
		t.Fatalf("SCIM failure fixture user creation status=%d read=%v", response.StatusCode, readErr)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(responseBody, &created); err != nil || created.ID == "" {
		t.Fatalf("SCIM failure fixture user response missing subject: decode=%v", err)
	}

	reference := waitForSCIMFailureEvent(t, client, nodes[0], created.ID, fixture, fixtureAdmin)
	assertSCIMFailureEvent(t, reference, created.ID)
	assertSCIMFailureAttempts(t, fixture, fixtureAdmin, created.ID, 5)
	for _, node := range nodes[1:] {
		event := waitForSCIMFailureEvent(t, client, node, created.ID, nil, "")
		assertSameSCIMFailureEvent(t, reference, event, node)
	}
	for _, node := range nodes {
		stream := collectStreamEvents(t, client, node, "latest=1000&level=critical", func(events []eventlog.Event) bool {
			return hasSCIMFailureEvent(events, created.ID)
		})
		matches := matchingSCIMFailureEvents(stream, created.ID)
		if len(matches) != 1 {
			t.Fatalf("SCIM failure SSE node=%s count=%d, want one", node, len(matches))
		}
		assertSameSCIMFailureEvent(t, reference, matches[0], node+" SSE")
	}

	state := scimFailureEventState{Subject: created.ID, Event: reference}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, encoded, 0o600); err != nil {
		t.Fatalf("write SCIM failure state: %v", err)
	}
}

func TestSCIMFailureEventPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SCIM_FAILURE_EVENT_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_SCIM_FAILURE_EVENT_PERSISTENCE=1 to run SCIM failure persistence E2E")
	}
	primary, secondary, tertiary, fixtureAdmin, username, password, statePath := scimFailureConfig(t)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read SCIM failure state: %v", err)
	}
	var state scimFailureEventState
	if err := json.Unmarshal(raw, &state); err != nil || state.Subject == "" {
		t.Fatalf("invalid SCIM failure state: decode=%v", err)
	}
	assertSCIMFailureEvent(t, state.Event, state.Subject)
	fixture := &http.Client{Timeout: 5 * time.Second}
	assertSCIMFailureAttempts(t, fixture, fixtureAdmin, state.Subject, 5)
	client := newBrowserClient(t)
	_, _ = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-failure-event-persisted", "scim-failure-event-persisted-nonce"), primary, secondary, username, password, "scim-failure-event-persisted")
	for _, node := range []string{primary, secondary, tertiary} {
		events := matchingSCIMFailureEvents(queryLifecycleEvents(t, client, node), state.Subject)
		if len(events) != 1 {
			t.Fatalf("persisted SCIM failure POST node=%s count=%d, want one", node, len(events))
		}
		assertSameSCIMFailureEvent(t, state.Event, events[0], node)
		stream := collectStreamEvents(t, client, node, "latest=1000&level=critical", func(events []eventlog.Event) bool {
			return hasSCIMFailureEvent(events, state.Subject)
		})
		matches := matchingSCIMFailureEvents(stream, state.Subject)
		if len(matches) != 1 {
			t.Fatalf("persisted SCIM failure SSE node=%s count=%d, want one", node, len(matches))
		}
		assertSameSCIMFailureEvent(t, state.Event, matches[0], node+" SSE")
	}
}

func scimFailureConfig(t *testing.T) (string, string, string, string, string, string, string) {
	t.Helper()
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	fixture := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SCIM_ADMIN_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	statePath := os.Getenv("GOAUTHY_E2E_SCIM_FAILURE_EVENT_STATE")
	if primary == "" || secondary == "" || tertiary == "" || fixture == "" || username == "" || password == "" || statePath == "" {
		t.Fatal("SCIM failure E2E requires all peer URLs, SCIM admin URL, browser credentials, and state path")
	}
	if !filepath.IsAbs(statePath) {
		t.Fatal("GOAUTHY_E2E_SCIM_FAILURE_EVENT_STATE must be absolute")
	}
	return primary, secondary, tertiary, fixture, username, password, statePath
}

func assertSCIMBootstrapProjection(t *testing.T, client *http.Client, fixture string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := client.Get(fixture + "/admin/state")
		if err == nil {
			var state struct {
				Users []struct {
					ExternalID string `json:"externalId"`
				} `json:"users"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil {
				for _, user := range state.Users {
					if user.ExternalID == "bootstrap-admin" {
						return
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for SCIM bootstrap projection")
		case <-ticker.C:
		}
	}
}

func setSCIMFixtureMode(t *testing.T, client *http.Client, fixture, mode string) {
	t.Helper()
	body := strings.NewReader(`{"mode":"` + mode + `"}`)
	request, err := http.NewRequest(http.MethodPost, fixture+"/admin/mode", body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("set SCIM fixture mode=%s: %v", mode, err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("set SCIM fixture mode=%s status=%d", mode, response.StatusCode)
	}
}

func waitForSCIMFailureEvent(t *testing.T, client *http.Client, base, subject string, fixtureClient *http.Client, fixture string) eventlog.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 26*time.Minute)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	lastCalls := -1
	for {
		if fixtureClient != nil {
			calls := scimFailureAttemptCount(t, fixtureClient, fixture, subject)
			if calls != lastCalls {
				t.Logf("SCIM target %s fixture calls=%d", subject, calls)
				lastCalls = calls
			}
		}
		events := matchingSCIMFailureEvents(queryLifecycleEvents(t, client, base), subject)
		if len(events) > 1 {
			t.Fatalf("SCIM failure event node=%s has %d target events", base, len(events))
		}
		if len(events) == 1 {
			return events[0]
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for SCIM failure event node=%s", base)
		case <-ticker.C:
		}
	}
}

func assertSCIMFailureAttempts(t *testing.T, client *http.Client, fixture, subject string, want int) {
	t.Helper()
	got := scimFailureAttemptCount(t, client, fixture, subject)
	if got != want {
		t.Fatalf("SCIM fixture target %s request count=%d, want %d", subject, got, want)
	}
}

func scimFailureAttemptCount(t *testing.T, client *http.Client, fixture, subject string) int {
	t.Helper()
	response, err := client.Get(fixture + "/admin/state")
	if err != nil {
		t.Fatalf("read SCIM fixture failure state: %v", err)
	}
	defer response.Body.Close()
	var state struct {
		Mode  string `json:"mode"`
		Users []struct {
			ExternalID string `json:"externalId"`
		} `json:"users"`
		Calls []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Filter string `json:"filter"`
		} `json:"calls"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state) != nil {
		t.Fatalf("SCIM fixture failure state status=%d", response.StatusCode)
	}
	if state.Mode != "temporary" {
		t.Fatalf("SCIM fixture mode=%q, want temporary failure throughout both phases", state.Mode)
	}
	for _, user := range state.Users {
		if user.ExternalID == subject {
			t.Fatalf("SCIM failed target %s unexpectedly exists remotely", subject)
		}
	}
	wantFilter := `externalId eq "` + subject + `"`
	count := 0
	for _, call := range state.Calls {
		if call.Method == http.MethodGet && call.Path == "/scim/v2/Users" && call.Filter == wantFilter {
			count++
		}
	}
	return count
}

func matchingSCIMFailureEvents(events []eventlog.Event, subject string) []eventlog.Event {
	matched := make([]eventlog.Event, 0, 1)
	wantText := "fixture / UserCreateUpdate(\"" + subject + "\")"
	for _, event := range events {
		if event.Type == eventlog.ScimTaskFailed && event.Text != nil && *event.Text == wantText {
			matched = append(matched, event)
		}
	}
	return matched
}

func hasSCIMFailureEvent(events []eventlog.Event, subject string) bool {
	return len(matchingSCIMFailureEvents(events, subject)) > 0
}

func assertSCIMFailureEvent(t *testing.T, event eventlog.Event, subject string) {
	t.Helper()
	wantText := "fixture / UserCreateUpdate(\"" + subject + "\")"
	if event.ID == "" || event.Timestamp <= 0 || event.Level != eventlog.Critical || event.Type != eventlog.ScimTaskFailed || event.IP != nil || event.Data == nil || *event.Data != 5 || event.Text == nil || *event.Text != wantText {
		t.Fatalf("invalid SCIM failure event: %+v", event)
	}
}

func assertSameSCIMFailureEvent(t *testing.T, want, got eventlog.Event, node string) {
	t.Helper()
	if want.ID != got.ID || want.Timestamp != got.Timestamp || want.Level != got.Level || want.Type != got.Type || !sameOptionalString(want.IP, got.IP) || !sameOptionalInt(want.Data, got.Data) || !sameOptionalString(want.Text, got.Text) {
		t.Fatalf("SCIM failure event differs node=%s want=%+v got=%+v", node, want, got)
	}
}

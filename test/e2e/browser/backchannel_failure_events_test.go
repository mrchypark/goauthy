package browser

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

const backchannelFailureClientID = "goauthy-dev"

type backchannelFailureEventState struct {
	Event        eventlog.Event `json:"event"`
	SinkAttempts int            `json:"sink_attempts"`
}

func TestBackchannelEventReaderHandlesBoundedRetryHistory(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
	}{{"small smoke history", 2}, {"full retry history over 64 KiB", 100}} {
		t.Run(tc.name, func(t *testing.T) {
			events := make([]backchannelEvent, tc.count)
			for i := range events {
				events[i] = backchannelEvent{Token: strings.Repeat("x", 700), Status: http.StatusServiceUnavailable}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(struct {
					Events []backchannelEvent `json:"events"`
				}{events})
			}))
			defer server.Close()
			got, err := backchannelEvents(server.Client(), server.URL)
			if err != nil || len(got) != len(events) {
				t.Fatalf("bounded retry history count=%d err=%v", len(got), err)
			}
			for i := range events {
				if got[i] != events[i] {
					t.Fatalf("retry history differs at %d", i)
				}
			}
		})
	}
}

// TestBackchannelFailureEvents exercises the production retry limit. The
// sink deliberately rejects all 100 attempts; completion must append one
// durable terminal event, rather than merely reporting a failed HTTP call.
func TestBackchannelFailureEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENTS=1 to run back-channel failure E2E")
	}
	primary, secondary, tertiary, username, password, clientSecret, sinkURL, statePath := backchannelFailureConfig(t)
	nodes := []string{primary, secondary, tertiary}
	setBackchannelSinkControl(t, sinkURL, 100, 0, http.StatusNoContent)

	// Keep the event observer independent from the browser being logged out.
	observer := newBrowserClient(t)
	observerVerifier := pkceVerifier(t)
	_, _ = loginForAuthorizationURL(t, observer, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(observerVerifier), "backchannel-failure-observer", "backchannel-failure-observer-nonce"), primary, secondary, username, password, "backchannel-failure-observer")

	for _, node := range nodes {
		if got := matchingBackchannelFailureEvents(t, observer, node); len(got) != 0 {
			t.Fatalf("node=%s already contains %d back-channel failure events", node, len(got))
		}
	}

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, _ = loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(verifier), username, password, "backchannel-failure-login")
	codeVerifier := pkceVerifier(t)
	code := authorizeWithCookie(t, client, tertiary, defaultRedirectURI, pkceChallenge(codeVerifier), "backchannel-failure-oidc", "backchannel-failure-nonce")
	tokens := exchangeCode(t, client, primary, clientSecret, defaultRedirectURI, code, codeVerifier)
	logout := do(t, client, http.MethodGet, logoutURL(t, secondary, tokens.IDToken, defaultPostLogoutRedirectURI, "backchannel-failure-logout"), nil, map[string]string{"Sec-Fetch-Site": "none"})
	logout.Body.Close()
	if logout.StatusCode != http.StatusSeeOther {
		t.Fatalf("public logout status=%d, want %d", logout.StatusCode, http.StatusSeeOther)
	}

	sinkClient := backchannelHTTPClient(t, sinkURL)
	waitForBackchannelAttemptCount(t, sinkClient, sinkURL, 100)

	var reference eventlog.Event
	for i, node := range nodes {
		events := waitForBackchannelFailureEvent(t, observer, node)
		if len(events) != 1 {
			t.Fatalf("node=%s back-channel failure event count=%d, want 1", node, len(events))
		}
		assertBackchannelFailureEvent(t, events[0])
		if i == 0 {
			reference = events[0]
		} else {
			assertSameBackchannelEvent(t, reference, events[0], node)
		}
		stream := collectStreamEvents(t, observer, node, "latest=100&level=critical", func(es []eventlog.Event) bool {
			return len(es) > 0 && es[len(es)-1].Type == eventlog.BackchannelLogoutFailed
		})
		matches := make([]eventlog.Event, 0, 1)
		for _, event := range stream {
			if event.Type == eventlog.BackchannelLogoutFailed {
				matches = append(matches, event)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("node=%s SSE back-channel failure event count=%d, want 1", node, len(matches))
		}
		assertSameBackchannelEvent(t, reference, matches[0], node+" SSE")
	}

	state := backchannelFailureEventState{Event: reference, SinkAttempts: 100}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatalf("write back-channel event state: %v", err)
	}
}

// TestBackchannelFailureEventPersisted is run after a same-data restart or
// pod replacement. It also checks that restart did not trigger another sink
// delivery attempt.
func TestBackchannelFailureEventPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_PERSISTENCE=1 to run back-channel event persistence E2E")
	}
	primary, secondary, tertiary, username, password, _, sinkURL, statePath := backchannelFailureConfig(t)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read back-channel event state: %v", err)
	}
	var state backchannelFailureEventState
	if err := json.Unmarshal(raw, &state); err != nil || state.SinkAttempts != 100 {
		t.Fatalf("invalid back-channel event state: decode=%v attempts=%d", err, state.SinkAttempts)
	}
	assertBackchannelFailureEvent(t, state.Event)
	if attempts, err := backchannelEvents(backchannelHTTPClient(t, sinkURL), sinkURL); err != nil {
		t.Fatalf("read sink attempts after restart: %v", err)
	} else if len(attempts) != 100 {
		t.Fatalf("sink attempts changed after restart: count=%d", len(attempts))
	} else {
		for i, attempt := range attempts {
			if attempt.Status != http.StatusServiceUnavailable {
				t.Fatalf("persisted sink attempt %d status=%d, want %d", i+1, attempt.Status, http.StatusServiceUnavailable)
			}
		}
	}

	observer := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, _ = loginForAuthorizationURL(t, observer, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "backchannel-failure-persisted", "backchannel-failure-persisted-nonce"), primary, secondary, username, password, "backchannel-failure-persisted")
	for _, node := range []string{primary, secondary, tertiary} {
		events := matchingBackchannelFailureEvents(t, observer, node)
		if len(events) != 1 {
			t.Fatalf("node=%s persisted back-channel event count=%d, want 1", node, len(events))
		}
		assertSameBackchannelEvent(t, state.Event, events[0], node)
		stream := collectStreamEvents(t, observer, node, "latest=100&level=critical", func(es []eventlog.Event) bool {
			return len(es) > 0 && es[len(es)-1].Type == eventlog.BackchannelLogoutFailed
		})
		matches := make([]eventlog.Event, 0, 1)
		for _, event := range stream {
			if event.Type == eventlog.BackchannelLogoutFailed {
				matches = append(matches, event)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("node=%s persisted SSE event count=%d, want 1", node, len(matches))
		}
		assertSameBackchannelEvent(t, state.Event, matches[0], node+" SSE")
	}
}

func backchannelFailureConfig(t *testing.T) (string, string, string, string, string, string, string, string) {
	t.Helper()
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	clientSecret, sinkURL := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET"), strings.TrimRight(os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL"), "/")
	statePath := os.Getenv("GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_STATE")
	if primary == "" || secondary == "" || tertiary == "" || username == "" || password == "" || clientSecret == "" || sinkURL == "" || statePath == "" {
		t.Fatal("back-channel failure E2E requires GOAUTHY_E2E_URL, all peer URLs, browser credentials, client secret, sink URL, and state path")
	}
	if !filepath.IsAbs(statePath) {
		t.Fatal("GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_STATE must be absolute")
	}
	return primary, secondary, tertiary, username, password, clientSecret, sinkURL, statePath
}

func waitForBackchannelAttemptCount(t *testing.T, client *http.Client, sinkURL string, want int) {
	t.Helper()
	deadline := time.NewTimer(6 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastCount, reported := 0, 0
	var lastErr error
	for {
		events, err := backchannelEvents(client, sinkURL)
		lastErr = err
		if err == nil {
			lastCount = len(events)
			if lastCount >= reported+25 {
				t.Logf("observed %d/%d back-channel attempts", lastCount, want)
				reported = lastCount
			}
			if len(events) > want {
				t.Fatalf("sink attempt count=%d exceeded %d", len(events), want)
			}
			if len(events) == want {
				for i, event := range events {
					if event.Status != http.StatusServiceUnavailable {
						t.Fatalf("sink attempt %d status=%d, want %d", i+1, event.Status, http.StatusServiceUnavailable)
					}
				}
				return
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %d sink attempts: last_count=%d read_error=%v", want, lastCount, lastErr)
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-ticker.C:
		}
	}
}

func matchingBackchannelFailureEvents(t *testing.T, client *http.Client, base string) []eventlog.Event {
	t.Helper()
	events := queryLifecycleEvents(t, client, base)
	filtered := make([]eventlog.Event, 0, 1)
	for _, event := range events {
		if event.Type == eventlog.BackchannelLogoutFailed {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func waitForBackchannelFailureEvent(t *testing.T, client *http.Client, base string) []eventlog.Event {
	t.Helper()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		events := matchingBackchannelFailureEvents(t, client, base)
		if len(events) > 1 {
			t.Fatalf("node=%s has %d back-channel failure events, want exactly one", base, len(events))
		}
		if len(events) == 1 {
			return events
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for back-channel failure event node=%s", base)
		case <-ticker.C:
		}
	}
}

func assertBackchannelFailureEvent(t *testing.T, event eventlog.Event) {
	t.Helper()
	if event.ID == "" || event.Timestamp <= 0 || event.Level != eventlog.Critical || event.Type != eventlog.BackchannelLogoutFailed || event.IP != nil || event.Data == nil || *event.Data != 100 || event.Text == nil || *event.Text != backchannelFailureClientID+" / " {
		t.Fatalf("invalid back-channel failure event: %+v", event)
	}
}

func assertSameBackchannelEvent(t *testing.T, want, got eventlog.Event, node string) {
	t.Helper()
	if want.ID != got.ID || want.Timestamp != got.Timestamp || want.Level != got.Level || want.Type != got.Type || !sameOptionalString(want.IP, got.IP) || !sameOptionalInt(want.Data, got.Data) || !sameOptionalString(want.Text, got.Text) {
		t.Fatalf("back-channel event differs node=%s want=%+v got=%+v", node, want, got)
	}
}

func sameOptionalString(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func sameOptionalInt(a, b *int64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

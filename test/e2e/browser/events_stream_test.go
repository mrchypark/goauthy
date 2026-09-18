package browser

import (
	"bufio"
	"bytes"
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

func TestCreationEventsStream(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_EVENTS_STREAM") != "1" {
		t.Skip("set GOAUTHY_E2E_EVENTS_STREAM=1 to run event stream E2E")
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
	_, sessionCookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "events-stream", "events-stream-nonce"), primary, secondary, username, password, "events-stream")

	ids := map[eventlog.Type]string{}
	for _, base := range nodes {
		events := collectStreamEvents(t, client, base, "latest=1000&level=info", func(events []eventlog.Event) bool {
			return hasEvent(events, "admin-created@goauthy.e2e", eventlog.NewUserRegistered) && hasEvent(events, "admin-created@goauthy.e2e", eventlog.NewRauthyAdmin) && hasEvent(events, "open@goauthy.e2e", eventlog.NewUserRegistered) && hasEvent(events, "Reset via Password Reset Form: open@goauthy.e2e", eventlog.UserPasswordReset)
		})
		for _, typ := range []eventlog.Type{eventlog.NewUserRegistered, eventlog.NewRauthyAdmin} {
			matches := matchingEvents(events, "admin-created@goauthy.e2e", typ)
			if len(matches) != 1 {
				t.Fatalf("history stream node=%s type=%s count=%d", base, typ, len(matches))
			}
			if prior := ids[typ]; prior != "" && prior != matches[0].ID {
				t.Fatalf("history stream ID differs node=%s type=%s", base, typ)
			}
			ids[typ] = matches[0].ID
		}
		ordinary := matchingEvents(events, "open@goauthy.e2e", eventlog.NewUserRegistered)
		if len(ordinary) != 1 || ordinary[0].Level != eventlog.Info || ordinary[0].Timestamp <= 0 || ordinary[0].Data != nil {
			t.Fatalf("history stream ordinary events node=%s: %+v", base, ordinary)
		}
		resetMatches := matchingEvents(events, "Reset via Password Reset Form: open@goauthy.e2e", eventlog.UserPasswordReset)
		if len(resetMatches) != 1 || resetMatches[0].Level != eventlog.Notice || resetMatches[0].Data != nil || resetMatches[0].IP == nil || resetMatches[0].Timestamp <= 0 {
			t.Fatalf("history stream password reset node=%s: %+v", base, resetMatches)
		}
		if prior := ids[eventlog.UserPasswordReset]; prior != "" && prior != resetMatches[0].ID {
			t.Fatalf("history stream reset ID differs node=%s", base)
		}
		ids[eventlog.UserPasswordReset] = resetMatches[0].ID
	}

	// latest=1&level=notice returns the single newest event with rank >= Notice.
	// Background events (e.g. LoginNewLocation at Warning rank) may outrank the
	// password-reset notice, so only assert structural invariants here.
	for _, base := range nodes {
		events := collectStreamEvents(t, client, base, "latest=1&level=notice", func(events []eventlog.Event) bool {
			return len(events) > 0
		})
		if len(events) != 1 || events[0].ID == "" || events[0].Timestamp <= 0 || events[0].Level.Rank() < eventlog.Notice.Rank() {
			t.Fatalf("notice stream node=%s events=%+v", base, events)
		}
	}

	// latest=0 starts after the historical high-water mark. Create a fresh
	// ordinary user on another peer and require its event to arrive live.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, secondary+"/auth/v1/events/stream?latest=0&level=info", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		response.Body.Close()
		t.Fatalf("live stream status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	scanner := bufio.NewScanner(response.Body)
	if !scanner.Scan() || scanner.Text() != "retry: 10000" || !scanner.Scan() || scanner.Text() != "" {
		response.Body.Close()
		t.Fatalf("latest=0 stream missing retry barrier")
	}
	csrf, _ := browsersession.DeriveCSRFToken(sessionCookie.Value)
	body, err := json.Marshal(map[string]any{"email": "stream-created@goauthy.e2e", "language": "en", "roles": []string{}, "given_name": "Stream", "family_name": "Created", "preferred_username": "stream-created"})
	if err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	created := do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	createdBody, _ := io.ReadAll(created.Body)
	created.Body.Close()
	if created.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("live stream fixture create status=%d body=%s", created.StatusCode, createdBody)
	}
	var result eventlog.Event
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &result); err != nil {
			response.Body.Close()
			t.Fatalf("live stream decode=%v", err)
		}
		// The first data frame after the barrier must be the newly-created event;
		// any earlier frame proves latest=0 leaked historical data.
		if result.Type != eventlog.NewUserRegistered || result.Level != eventlog.Info || result.Text == nil || *result.Text != "stream-created@goauthy.e2e" || result.Timestamp <= 0 || result.Data != nil {
			response.Body.Close()
			t.Fatalf("live stream first event=%+v", result)
		}
		response.Body.Close()
		return
	}
	response.Body.Close()
	t.Fatalf("live stream ended before new event: %v", scanner.Err())
}

func collectStreamEvents(t *testing.T, client *http.Client, base, query string, done func([]eventlog.Event) bool) []eventlog.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/auth/v1/events/stream?"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream node=%s status=%d content-type=%q", base, response.StatusCode, response.Header.Get("Content-Type"))
	}
	var events []eventlog.Event
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event eventlog.Event
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatalf("stream node=%s decode=%v", base, err)
		}
		events = append(events, event)
		if done(events) {
			return events
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("stream node=%s read=%v", base, err)
	}
	t.Fatalf("stream node=%s ended before expected events", base)
	return nil
}

func matchingEvents(events []eventlog.Event, email string, typ eventlog.Type) []eventlog.Event {
	matched := make([]eventlog.Event, 0, 1)
	for _, event := range events {
		if event.Type == typ && event.Text != nil && *event.Text == email {
			matched = append(matched, event)
		}
	}
	return matched
}

func hasEvent(events []eventlog.Event, email string, typ eventlog.Type) bool {
	return len(matchingEvents(events, email, typ)) > 0
}

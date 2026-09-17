package browser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestEventTestEndpoint(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_EVENT_TEST") != "1" {
		t.Skip("set GOAUTHY_E2E_EVENT_TEST=1 to run event test endpoint E2E")
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
	_, sessionCookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "event-test", "event-test-nonce"), primary, secondary, username, password, "event-test")
	csrf, _ := browsersession.DeriveCSRFToken(sessionCookie.Value)

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
		t.Fatalf("stream status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	scanner := bufio.NewScanner(response.Body)
	if !scanner.Scan() || scanner.Text() != "retry: 10000" || !scanner.Scan() || scanner.Text() != "" {
		response.Body.Close()
		t.Fatal("stream missing retry barrier")
	}

	// Browser-admin CSRF is mandatory and this rejected request must not emit.
	withoutCSRF := do(t, client, http.MethodPost, primary+"/auth/v1/events/test", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	withoutBody, _ := io.ReadAll(withoutCSRF.Body)
	withoutCSRF.Body.Close()
	if withoutCSRF.StatusCode != http.StatusUnauthorized && withoutCSRF.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("missing CSRF status=%d body=%s", withoutCSRF.StatusCode, withoutBody)
	}

	created := do(t, client, http.MethodPost, primary+"/auth/v1/events/test", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	createdBody, _ := io.ReadAll(created.Body)
	created.Body.Close()
	if created.StatusCode != http.StatusOK || len(createdBody) != 0 {
		response.Body.Close()
		t.Fatalf("test event status=%d body=%q", created.StatusCode, createdBody)
	}

	var streamEvent eventlog.Event
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &streamEvent); err != nil {
			response.Body.Close()
			t.Fatal(err)
		}
		break
	}
	response.Body.Close()
	if streamEvent.Type != eventlog.Test || streamEvent.Level != eventlog.Info || streamEvent.Text == nil || *streamEvent.Text != "This is a Test-Event" || streamEvent.Data != nil || streamEvent.Timestamp <= 0 || streamEvent.IP == nil {
		t.Fatalf("invalid streamed test event=%+v", streamEvent)
	}
	if _, err := netip.ParseAddr(*streamEvent.IP); err != nil {
		t.Fatalf("invalid streamed event IP=%q", *streamEvent.IP)
	}

	// Exercise both API-key authorization branches. The create-capable key
	// necessarily appends a second durable test event, which is accounted for
	// explicitly below; the read-only key must not append one.
	createKey := createAdminAPIKey(t, client, primary, csrf, "event-test-create", []apiKeyAccess{{Group: "Events", AccessRights: []string{"create"}}})
	readKey := createAdminAPIKey(t, client, primary, csrf, "event-test-read", []apiKeyAccess{{Group: "Events", AccessRights: []string{"read"}}})
	defer func() {
		apiKeyStatus(t, client, http.MethodDelete, primary+"/auth/v1/api_keys/event-test-create", nil, rbacMutationHeaders(csrf), http.StatusOK, "create key cleanup")
		apiKeyStatus(t, client, http.MethodDelete, primary+"/auth/v1/api_keys/event-test-read", nil, rbacMutationHeaders(csrf), http.StatusOK, "read key cleanup")
	}()
	apiKeyStatus(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/events/test", nil, map[string]string{"Authorization": "API-Key " + readKey}, http.StatusForbidden, "read-only key cannot create test event")
	apiKeyStatus(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/events/test", nil, map[string]string{"Authorization": "API-Key " + createKey}, http.StatusOK, "create-only key creates test event")

	referenceIDs := map[string]struct{}{}
	for _, base := range nodes {
		body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info","typ":"Test"}`))
		query := do(t, client, http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
		var events []eventlog.Event
		err := json.NewDecoder(query.Body).Decode(&events)
		query.Body.Close()
		if query.StatusCode != http.StatusOK || err != nil || len(events) != 2 {
			t.Fatalf("test event query node=%s status=%d decode=%v events=%d", base, query.StatusCode, err, len(events))
		}
		seenStream := false
		nodeIDs := make(map[string]struct{}, len(events))
		for _, event := range events {
			if event.ID == streamEvent.ID {
				seenStream = true
			}
			nodeIDs[event.ID] = struct{}{}
			if event.Type != eventlog.Test || event.Level != eventlog.Info || event.Data != nil || event.Timestamp <= 0 || event.Text == nil || *event.Text != "This is a Test-Event" || event.IP == nil {
				t.Fatalf("invalid queried test event node=%s event=%+v", base, event)
			}
			if _, err := netip.ParseAddr(*event.IP); err != nil {
				t.Fatalf("invalid queried event IP node=%s ip=%q", base, *event.IP)
			}
		}
		if !seenStream {
			t.Fatalf("queried test events node=%s omitted streamed event %s", base, streamEvent.ID)
		}
		if len(referenceIDs) == 0 {
			referenceIDs = nodeIDs
		} else if len(referenceIDs) != len(nodeIDs) {
			t.Fatalf("test event IDs differ node=%s", base)
		} else {
			for id := range referenceIDs {
				if _, ok := nodeIDs[id]; !ok {
					t.Fatalf("test event ID differs node=%s", base)
				}
			}
		}
	}
}

func TestEventTestPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_EVENT_TEST_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_EVENT_TEST_PERSISTENCE=1 to run persisted test-event E2E")
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
	_, _ = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "event-test-persistence", "event-test-persistence-nonce"), primary, secondary, username, password, "event-test-persistence")

	var expected map[string]struct{}
	for _, base := range nodes {
		events := queryTestEvents(t, client, base)
		ids := make(map[string]struct{}, len(events))
		for _, event := range events {
			if event.Type != eventlog.Test || event.Level != eventlog.Info || event.Text == nil || *event.Text != "This is a Test-Event" || event.Data != nil || event.Timestamp <= 0 || event.IP == nil {
				t.Fatalf("invalid persisted test event node=%s event=%+v", base, event)
			}
			if _, err := netip.ParseAddr(*event.IP); err != nil {
				t.Fatalf("invalid persisted event IP node=%s ip=%q", base, *event.IP)
			}
			ids[event.ID] = struct{}{}
		}
		if expected == nil {
			expected = ids
		} else if len(expected) != len(ids) {
			t.Fatalf("persisted test event IDs differ node=%s", base)
		} else {
			for id := range expected {
				if _, ok := ids[id]; !ok {
					t.Fatalf("persisted test event ID differs node=%s", base)
				}
			}
		}
		stream := collectStreamEvents(t, client, base, "latest=1000&level=info", func(events []eventlog.Event) bool {
			count := 0
			for _, event := range events {
				if event.Type == eventlog.Test && event.Text != nil && *event.Text == "This is a Test-Event" {
					count++
				}
			}
			return count == 2
		})
		streamIDs := make(map[string]struct{}, 2)
		for _, event := range stream {
			if event.Type == eventlog.Test && event.Text != nil && *event.Text == "This is a Test-Event" {
				if event.Level != eventlog.Info || event.Data != nil || event.Timestamp <= 0 || event.IP == nil {
					t.Fatalf("invalid persisted SSE Test event node=%s event=%+v", base, event)
				}
				if _, err := netip.ParseAddr(*event.IP); err != nil {
					t.Fatalf("invalid persisted SSE event IP node=%s ip=%q", base, *event.IP)
				}
				streamIDs[event.ID] = struct{}{}
			}
		}
		if len(streamIDs) != 2 {
			t.Fatalf("persisted SSE Test events node=%s count=%d", base, len(streamIDs))
		}
		for id := range expected {
			if _, ok := streamIDs[id]; !ok {
				t.Fatalf("persisted SSE event ID differs node=%s", base)
			}
		}
	}
}

func queryTestEvents(t *testing.T, client *http.Client, base string) []eventlog.Event {
	t.Helper()
	body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info","typ":"Test"}`))
	response := do(t, client, http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	var events []eventlog.Event
	err := json.NewDecoder(response.Body).Decode(&events)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || len(events) != 2 {
		t.Fatalf("test event query node=%s status=%d decode=%v count=%d", base, response.StatusCode, err, len(events))
	}
	return events
}

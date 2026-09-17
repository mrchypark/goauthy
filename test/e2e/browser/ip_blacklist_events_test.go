package browser

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestIPBlacklistEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_IP_BLACKLIST_EVENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_IP_BLACKLIST_EVENTS=1 to run blacklist event E2E")
	}
	statePath := requiredIPBlacklistEventState(t)
	primary, secondary, username, password, _ := requiredIPBlacklistEventConfig(t)
	testIP := os.Getenv("GOAUTHY_E2E_IP_BLACKLIST_TEST_IP")
	if _, err := netip.ParseAddr(testIP); err != nil || testIP == "" {
		t.Fatal("GOAUTHY_E2E_IP_BLACKLIST_TEST_IP must be a valid host IP")
	}
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		tertiary = secondary
	}
	nodes := []string{primary, secondary, tertiary}
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "ip-blacklist-events", "ip-blacklist-events-nonce"), primary, secondary, username, password, "ip-blacklist-events")
	csrf, _ := browsersession.DeriveCSRFToken(cookie.Value)
	key := createAdminAPIKey(t, client, primary, csrf, "ip-blacklist-events", []apiKeyAccess{{Group: "Events", AccessRights: []string{"read"}}})
	defer apiKeyStatus(t, client, http.MethodDelete, primary+"/auth/v1/api_keys/ip-blacklist-events", nil, rbacMutationHeaders(csrf), http.StatusOK, "blacklist event key cleanup")
	for _, base := range nodes {
		if got := queryIPBlacklistEvents(t, key, base); len(got) != 0 {
			t.Fatalf("blacklist event existed before failures node=%s count=%d", base, len(got))
		}
		if got := queryInvalidLoginEvents(t, key, base, testIP); len(got) != 0 {
			t.Fatalf("invalid-login events existed before failures node=%s count=%d", base, len(got))
		}
	}

	for i := 0; i < 7; i++ {
		target := nodes[i%len(nodes)]
		failureClient := newBrowserClient(t)
		failureClient.Timeout = 60 * time.Second
		response := do(t, failureClient, http.MethodGet, authorizationURL(t, target, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "ip-blacklist-failure"+string(rune('0'+i))), nil, map[string]string{"X-Forwarded-For": testIP})
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("failure init %d status=%d", i+1, response.StatusCode)
		}
		interaction := loginInteraction(t, response)
		response.Body.Close()
		response = do(t, failureClient, http.MethodPost, target+"/auth/login", strings.NewReader(url.Values{"interaction": {interaction}, "username": {username}, "password": {password + "-wrong"}}.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin", "X-Forwarded-For": testIP})
		status := response.StatusCode
		response.Body.Close()
		if i < 6 && status != http.StatusUnauthorized {
			t.Fatalf("failure %d status=%d", i+1, status)
		}
		if i == 6 && status != http.StatusTooManyRequests {
			t.Fatalf("blacklist trigger status=%d", status)
		}
		for _, base := range nodes {
			events := queryInvalidLoginEvents(t, key, base, testIP)
			if len(events) != i+1 {
				t.Fatalf("invalid-login event count failure=%d node=%s count=%d", i+1, base, len(events))
			}
			seen := make(map[int64]bool, i+1)
			for _, event := range events {
				if event.Type != eventlog.InvalidLogins || event.ID == "" || event.IP == nil || *event.IP != testIP || event.Data == nil || *event.Data <= 0 || *event.Data > int64(i+1) || seen[*event.Data] || event.Level != invalidLoginLevel(int(*event.Data)) || event.Text != nil || event.Timestamp <= 0 {
					t.Fatalf("invalid-login event failure=%d node=%s event=%+v", i+1, base, event)
				}
				seen[*event.Data] = true
			}
		}
	}

	eventID := ""
	var event eventlog.Event
	var invalidEvents []eventlog.Event
	for _, base := range nodes {
		events := queryIPBlacklistEvents(t, key, base)
		if len(events) != 1 {
			t.Fatalf("blacklist event count node=%s count=%d", base, len(events))
		}
		candidate := events[0]
		if candidate.Type != eventlog.IpBlacklisted || candidate.Level != eventlog.Warning || candidate.IP == nil || *candidate.IP != testIP || candidate.Data == nil || *candidate.Data != candidate.Timestamp/1000+60 || candidate.Text != nil || candidate.ID == "" || candidate.Timestamp <= 0 {
			t.Fatalf("invalid blacklist event node=%s event=%+v", base, candidate)
		}
		if eventID == "" {
			eventID, event = candidate.ID, candidate
		} else if eventID != candidate.ID || event.Timestamp != candidate.Timestamp || *event.Data != *candidate.Data {
			t.Fatalf("blacklist event differs node=%s", base)
		}
		currentInvalid := queryInvalidLoginEvents(t, key, base, testIP)
		if invalidEvents == nil {
			invalidEvents = currentInvalid
		} else {
			assertInvalidLoginEventsEqual(t, base, invalidEvents, currentInvalid)
		}
	}
	stream := collectStreamEvents(t, client, secondary, "latest=100&level=warning", func(events []eventlog.Event) bool {
		for _, candidate := range events {
			if candidate.Type == eventlog.IpBlacklisted && candidate.IP != nil && *candidate.IP == testIP {
				return true
			}
		}
		return false
	})
	streamMatches := make([]eventlog.Event, 0, 1)
	for _, candidate := range stream {
		if candidate.Type == eventlog.IpBlacklisted && candidate.IP != nil && *candidate.IP == testIP {
			streamMatches = append(streamMatches, candidate)
		}
	}
	if len(streamMatches) != 1 || streamMatches[0].ID != eventID || streamMatches[0].Level != eventlog.Warning || streamMatches[0].IP == nil || *streamMatches[0].IP != testIP || streamMatches[0].Data == nil || *streamMatches[0].Data != *event.Data || streamMatches[0].Timestamp != event.Timestamp || streamMatches[0].Text != nil {
		t.Fatalf("invalid blacklist SSE events=%+v", streamMatches)
	}
	invalidStream := collectStreamEvents(t, client, secondary, "latest=100&level=info", func(events []eventlog.Event) bool {
		count := 0
		for _, candidate := range events {
			if candidate.Type == eventlog.InvalidLogins && candidate.IP != nil && *candidate.IP == testIP {
				count++
			}
		}
		return count == 7
	})
	invalidMatches := make([]eventlog.Event, 0, 7)
	for _, candidate := range invalidStream {
		if candidate.Type == eventlog.InvalidLogins && candidate.IP != nil && *candidate.IP == testIP {
			invalidMatches = append(invalidMatches, candidate)
		}
	}
	if len(invalidMatches) != 7 {
		t.Fatalf("invalid-login SSE event count=%d", len(invalidMatches))
	}
	assertInvalidLoginEventsEqual(t, "SSE", invalidEvents, invalidMatches)

	for _, base := range nodes {
		blocked := do(t, newBrowserClient(t), http.MethodGet, authorizationURL(t, base, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "ip-blacklist-blocked"), nil, map[string]string{"X-Forwarded-For": testIP})
		blocked.Body.Close()
		if blocked.StatusCode != http.StatusForbidden {
			t.Fatalf("blocked request node=%s status=%d", base, blocked.StatusCode)
		}
		if got := queryIPBlacklistEvents(t, key, base); len(got) != 1 {
			t.Fatalf("blocked request appended event node=%s count=%d", base, len(got))
		}
		if got := queryInvalidLoginEvents(t, key, base, testIP); len(got) != 7 {
			t.Fatalf("blocked request appended invalid-login event node=%s count=%d", base, len(got))
		}
	}
	state, _ := json.Marshal(struct {
		ID        string           `json:"id"`
		Timestamp int64            `json:"timestamp"`
		IP        string           `json:"ip"`
		Data      int64            `json:"data"`
		Invalid   []eventlog.Event `json:"invalid_logins"`
	}{event.ID, event.Timestamp, *event.IP, *event.Data, invalidEvents})
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		t.Fatalf("write blacklist event state: %v", err)
	}
}

func TestIPBlacklistEventPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_IP_BLACKLIST_EVENT_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_IP_BLACKLIST_EVENT_PERSISTENCE=1 to run blacklist event persistence E2E")
	}
	statePath := requiredIPBlacklistEventState(t)
	var state struct {
		ID        string           `json:"id"`
		Timestamp int64            `json:"timestamp"`
		IP        string           `json:"ip"`
		Data      int64            `json:"data"`
		Invalid   []eventlog.Event `json:"invalid_logins"`
	}
	raw, err := os.ReadFile(statePath)
	if err != nil || json.Unmarshal(raw, &state) != nil || state.ID == "" || state.Timestamp <= 0 || state.IP == "" || state.Data <= 0 || len(state.Invalid) != 7 {
		t.Fatalf("invalid blacklist event state %s", statePath)
	}
	primary, secondary, username, password, _ := requiredIPBlacklistEventConfig(t)
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		tertiary = secondary
	}
	nodes := []string{primary, secondary, tertiary}
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, _ = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "ip-blacklist-event-persistence", "ip-blacklist-event-persistence-nonce"), primary, secondary, username, password, "ip-blacklist-event-persistence")
	for _, base := range nodes {
		events := queryIPBlacklistEventsBrowser(t, client, base)
		if len(events) != 1 || events[0].ID != state.ID || events[0].Timestamp != state.Timestamp || events[0].IP == nil || *events[0].IP != state.IP || events[0].Data == nil || *events[0].Data != state.Data || events[0].Level != eventlog.Warning || events[0].Text != nil {
			t.Fatalf("persisted blacklist event node=%s events=%+v", base, events)
		}
		invalid := queryInvalidLoginEventsBrowser(t, client, base, state.IP)
		assertInvalidLoginEventsEqual(t, base, state.Invalid, invalid)
		stream := collectStreamEvents(t, client, base, "latest=100&level=warning", func(events []eventlog.Event) bool {
			for _, event := range events {
				if event.ID == state.ID {
					return true
				}
			}
			return false
		})
		matches := make([]eventlog.Event, 0, 1)
		for _, event := range stream {
			if event.ID == state.ID {
				matches = append(matches, event)
			}
		}
		if len(matches) != 1 || matches[0].Type != eventlog.IpBlacklisted || matches[0].Level != eventlog.Warning || matches[0].Timestamp != state.Timestamp || matches[0].IP == nil || *matches[0].IP != state.IP || matches[0].Data == nil || *matches[0].Data != state.Data || matches[0].Text != nil {
			t.Fatalf("persisted blacklist SSE node=%s events=%+v", base, matches)
		}
		invalidStream := collectStreamEvents(t, client, base, "latest=100&level=info", func(events []eventlog.Event) bool {
			count := 0
			for _, event := range events {
				if event.Type == eventlog.InvalidLogins && event.IP != nil && *event.IP == state.IP {
					count++
				}
			}
			return count == 7
		})
		invalidMatches := make([]eventlog.Event, 0, 7)
		for _, event := range invalidStream {
			if event.Type == eventlog.InvalidLogins && event.IP != nil && *event.IP == state.IP {
				invalidMatches = append(invalidMatches, event)
			}
		}
		assertInvalidLoginEventsEqual(t, base+" SSE", state.Invalid, invalidMatches)
	}
}

func requiredIPBlacklistEventConfig(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || secondary == "" || username == "" || password == "" || secret == "" {
		t.Fatal("GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, browser username/password, and client secret are required")
	}
	return primary, secondary, username, password, secret
}

func requiredIPBlacklistEventState(t *testing.T) string {
	t.Helper()
	path := os.Getenv("GOAUTHY_E2E_IP_BLACKLIST_EVENT_STATE")
	if path == "" || !filepath.IsAbs(path) {
		t.Fatal("GOAUTHY_E2E_IP_BLACKLIST_EVENT_STATE must be an absolute path")
	}
	return path
}

func queryIPBlacklistEvents(t *testing.T, secret, base string) []eventlog.Event {
	t.Helper()
	body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"warning","typ":"IpBlacklisted"}`))
	response := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	var events []eventlog.Event
	err := json.NewDecoder(response.Body).Decode(&events)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("blacklist event query node=%s status=%d decode=%v", base, response.StatusCode, err)
	}
	return events
}

func queryIPBlacklistEventsBrowser(t *testing.T, client *http.Client, base string) []eventlog.Event {
	t.Helper()
	body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"warning","typ":"IpBlacklisted"}`))
	response := do(t, client, http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	var events []eventlog.Event
	err := json.NewDecoder(response.Body).Decode(&events)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("blacklist browser event query node=%s status=%d decode=%v", base, response.StatusCode, err)
	}
	return events
}

func invalidLoginLevel(count int) eventlog.Level {
	switch {
	case count >= 20:
		return eventlog.Critical
	case count >= 10:
		return eventlog.Warning
	case count >= 7:
		return eventlog.Notice
	default:
		return eventlog.Info
	}
}

func queryInvalidLoginEvents(t *testing.T, secret, base, ip string) []eventlog.Event {
	t.Helper()
	body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info","typ":"InvalidLogins"}`))
	response := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	var all []eventlog.Event
	err := json.NewDecoder(response.Body).Decode(&all)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("invalid-login event query node=%s status=%d decode=%v", base, response.StatusCode, err)
	}
	events := make([]eventlog.Event, 0, len(all))
	for _, event := range all {
		if event.Type == eventlog.InvalidLogins && event.IP != nil && *event.IP == ip {
			events = append(events, event)
		}
	}
	return events
}

func queryInvalidLoginEventsBrowser(t *testing.T, client *http.Client, base, ip string) []eventlog.Event {
	t.Helper()
	body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info","typ":"InvalidLogins"}`))
	response := do(t, client, http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	var all []eventlog.Event
	err := json.NewDecoder(response.Body).Decode(&all)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("invalid-login browser event query node=%s status=%d decode=%v", base, response.StatusCode, err)
	}
	events := make([]eventlog.Event, 0, len(all))
	for _, event := range all {
		if event.Type == eventlog.InvalidLogins && event.IP != nil && *event.IP == ip {
			events = append(events, event)
		}
	}
	return events
}

func assertInvalidLoginEventsEqual(t *testing.T, node string, want, got []eventlog.Event) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("invalid-login event count node=%s want=%d got=%d", node, len(want), len(got))
	}
	// POST sorts by timestamp descending; SSE uses commit order. Compare
	// identity and payload, not the unrelated transport-specific ordering.
	byID := make(map[string]eventlog.Event, len(want))
	for _, event := range want {
		if event.ID == "" {
			t.Fatal("invalid-login event has empty ID")
		}
		if _, duplicate := byID[event.ID]; duplicate {
			t.Fatal("duplicate invalid-login event ID")
		}
		byID[event.ID] = event
	}
	for _, event := range got {
		expected, ok := byID[event.ID]
		if !ok || expected.Type != eventlog.InvalidLogins || event.Type != eventlog.InvalidLogins || expected.Timestamp != event.Timestamp || expected.Level != event.Level || expected.IP == nil || event.IP == nil || *expected.IP != *event.IP || expected.Data == nil || event.Data == nil || *expected.Data != *event.Data || expected.Text != nil || event.Text != nil {
			t.Fatalf("invalid-login event differs node=%s want=%+v got=%+v", node, expected, event)
		}
		delete(byID, event.ID)
	}
}

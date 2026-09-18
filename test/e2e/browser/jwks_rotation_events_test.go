package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestJWKSRotationEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_JWKS_ROTATION_EVENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_JWKS_ROTATION_EVENTS=1 to run JWKS rotation event E2E")
	}
	if os.Getenv("GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION") != "1" {
		t.Fatal("GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1 is required for the five-minute live rotation gate")
	}
	statePath := requiredJWKSStatePath(t)
	primary, secondary, username, password, _ := requiredJWKSRotationConfig(t)
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		tertiary = secondary
	}
	nodes := []string{primary, secondary, tertiary}
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "jwks-rotation-events", "jwks-rotation-events-nonce"), primary, secondary, username, password, "jwks-rotation-events")
	csrf, _ := browsersession.DeriveCSRFToken(cookie.Value)
	key := createAdminAPIKey(t, client, primary, csrf, "jwks-rotation-events", []apiKeyAccess{{Group: "Events", AccessRights: []string{"read"}}})
	defer apiKeyStatus(t, client, http.MethodDelete, primary+"/auth/v1/api_keys/jwks-rotation-events", nil, rbacMutationHeaders(csrf), http.StatusOK, "JWKS rotation event key cleanup")

	initial := publicJWKSWithHeaders(t, client, primary)
	if len(initial.keys.Keys) != 2 || initial.keys.Keys[0].KeyID == "" || initial.keys.Keys[1].KeyID == "" || initial.headers.Get("ETag") == "" || !strings.Contains(initial.headers.Get("Cache-Control"), "max-age=300") {
		t.Fatalf("public JWKS must expose active+pending keys with cache validators: keys=%d etag=%q cache=%q", len(initial.keys.Keys), initial.headers.Get("ETag"), initial.headers.Get("Cache-Control"))
	}
	for _, base := range nodes {
		peer := publicJWKS(t, client, base)
		if len(peer.Keys) != 2 || peer.Keys[0].KeyID != initial.keys.Keys[0].KeyID || peer.Keys[1].KeyID != initial.keys.Keys[1].KeyID {
			t.Fatalf("initial active+pending JWKS differs node=%s", base)
		}
	}
	for _, base := range nodes {
		if got := queryJWKSRotationEvents(t, key, base); len(got) != 0 {
			t.Fatalf("rotation events existed before observed rotation node=%s count=%d", base, len(got))
		}
	}

	deadline := time.NewTimer(8 * time.Minute)
	defer deadline.Stop()
	poll := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	rotated := false
	for !rotated {
		current := publicJWKS(t, client, primary)
		if len(current.Keys) == 0 || current.Keys[0].KeyID == "" {
			t.Fatal("public JWKS lost active key")
		}
		rotated = current.Keys[0].KeyID == initial.keys.Keys[1].KeyID && current.Keys[0].KeyID != initial.keys.Keys[0].KeyID
		if rotated {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("active JWKS key did not rotate within 8m")
		case <-poll.C:
		}
	}

	var eventID string
	var eventTimestamp int64
	for _, base := range nodes {
		events := queryJWKSRotationEvents(t, key, base)
		if len(events) != 1 {
			t.Fatalf("rotation event count node=%s count=%d", base, len(events))
		}
		event := events[0]
		if event.Type != eventlog.JwksRotated || event.Level != eventlog.Notice || event.IP != nil || event.Data != nil || event.Text != nil || event.Timestamp <= 0 || event.ID == "" {
			t.Fatalf("invalid JWKS rotation event node=%s event=%+v", base, event)
		}
		if eventID == "" {
			eventID = event.ID
			eventTimestamp = event.Timestamp
		} else if eventID != event.ID || eventTimestamp != event.Timestamp {
			t.Fatalf("rotation event ID differs node=%s", base)
		}
		if current := publicJWKS(t, client, base); len(current.Keys) < 2 || current.Keys[0].KeyID != initial.keys.Keys[1].KeyID || !containsJWKSKey(current, initial.keys.Keys[0].KeyID) {
			t.Fatalf("rotated JWKS node=%s did not activate pending key while retaining old key", base)
		}
		current := publicJWKSWithHeaders(t, client, base)
		if current.headers.Get("ETag") == "" || current.headers.Get("ETag") == initial.headers.Get("ETag") || current.headers.Get("Cache-Control") != "public, max-age=300, must-revalidate" {
			t.Fatalf("rotated JWKS validators node=%s headers=%v", base, current.headers)
		}
		conditional := do(t, client, http.MethodGet, base+"/oidc/jwks.json", nil, map[string]string{"If-None-Match": current.headers.Get("ETag")})
		conditional.Body.Close()
		if conditional.StatusCode != http.StatusNotModified || conditional.Header.Get("ETag") != current.headers.Get("ETag") {
			t.Fatalf("conditional rotated JWKS node=%s status=%d", base, conditional.StatusCode)
		}
		stream := collectStreamEvents(t, client, base, "latest=100&level=notice", func(events []eventlog.Event) bool {
			for _, candidate := range events {
				if candidate.Type == eventlog.JwksRotated {
					return true
				}
			}
			return false
		})
		streamMatches := make([]eventlog.Event, 0, 1)
		for _, candidate := range stream {
			if candidate.Type == eventlog.JwksRotated {
				streamMatches = append(streamMatches, candidate)
			}
		}
		if len(streamMatches) != 1 || streamMatches[0].ID != eventID || streamMatches[0].Timestamp != eventTimestamp || streamMatches[0].Level != eventlog.Notice || streamMatches[0].IP != nil || streamMatches[0].Data != nil || streamMatches[0].Text != nil {
			t.Fatalf("invalid JWKS rotation SSE node=%s events=%+v", base, streamMatches)
		}
	}
	state, err := json.Marshal(struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"timestamp"`
		ActiveKID string `json:"active_kid"`
	}{eventID, eventTimestamp, initial.keys.Keys[1].KeyID})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		t.Fatalf("write JWKS rotation state: %v", err)
	}
}

func TestJWKSRotationEventPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_JWKS_EVENT_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_JWKS_EVENT_PERSISTENCE=1 to run JWKS event persistence E2E")
	}
	primary, secondary, username, password, _ := requiredJWKSRotationConfig(t)
	statePath := requiredJWKSStatePath(t)
	var state struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"timestamp"`
		ActiveKID string `json:"active_kid"`
	}
	stateBody, err := os.ReadFile(statePath)
	if err != nil || json.Unmarshal(stateBody, &state) != nil || state.ID == "" || state.Timestamp <= 0 || state.ActiveKID == "" {
		t.Fatalf("invalid JWKS rotation state file %s", statePath)
	}
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		tertiary = secondary
	}
	nodes := []string{primary, secondary, tertiary}
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, _ = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "jwks-event-persistence", "jwks-event-persistence-nonce"), primary, secondary, username, password, "jwks-event-persistence")
	var eventID string
	for _, base := range nodes {
		events := queryJWKSRotationEventsBrowser(t, client, base)
		if len(events) != 1 {
			t.Fatalf("persisted rotation event count node=%s count=%d", base, len(events))
		}
		event := events[0]
		if event.Type != eventlog.JwksRotated || event.Level != eventlog.Notice || event.IP != nil || event.Data != nil || event.Text != nil || event.Timestamp <= 0 || event.ID == "" {
			t.Fatalf("invalid persisted rotation event node=%s event=%+v", base, event)
		}
		if eventID == "" {
			eventID = event.ID
		} else if eventID != event.ID {
			t.Fatalf("persisted rotation event ID differs node=%s", base)
		}
		if event.ID != state.ID || event.Timestamp != state.Timestamp {
			t.Fatalf("persisted rotation event changed node=%s", base)
		}
		current := publicJWKS(t, client, base)
		if len(current.Keys) == 0 || current.Keys[0].KeyID != state.ActiveKID {
			t.Fatalf("persisted active JWKS key changed node=%s", base)
		}
		stream := collectStreamEvents(t, client, base, "latest=100&level=notice", func(events []eventlog.Event) bool {
			for _, candidate := range events {
				if candidate.Type == eventlog.JwksRotated {
					return true
				}
			}
			return false
		})
		matches := make([]eventlog.Event, 0, 1)
		for _, candidate := range stream {
			if candidate.Type == eventlog.JwksRotated {
				matches = append(matches, candidate)
			}
		}
		if len(matches) != 1 || matches[0].ID != eventID || matches[0].Timestamp != state.Timestamp || matches[0].Level != eventlog.Notice || matches[0].IP != nil || matches[0].Data != nil || matches[0].Text != nil {
			t.Fatalf("persisted rotation SSE node=%s events=%+v", base, matches)
		}
	}
}

func requiredJWKSRotationConfig(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	secret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || secondary == "" || username == "" || password == "" || secret == "" {
		t.Fatal("GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, browser username/password, and client secret are required")
	}
	return primary, secondary, username, password, secret
}

func requiredJWKSStatePath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("GOAUTHY_E2E_JWKS_EVENT_STATE")
	if path == "" || !filepath.IsAbs(path) {
		t.Fatal("GOAUTHY_E2E_JWKS_EVENT_STATE must be an absolute path")
	}
	return path
}

type publicJWKSResponse struct {
	keys    jose.JSONWebKeySet
	headers http.Header
}

func publicJWKSWithHeaders(t *testing.T, client *http.Client, base string) publicJWKSResponse {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/oidc/jwks.json", nil, nil)
	defer response.Body.Close()
	var keys jose.JSONWebKeySet
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&keys) != nil {
		t.Fatalf("JWKS status=%d", response.StatusCode)
	}
	return publicJWKSResponse{keys: keys, headers: response.Header}
}

func containsJWKSKey(keys jose.JSONWebKeySet, kid string) bool {
	for _, key := range keys.Keys {
		if key.KeyID == kid {
			return true
		}
	}
	return false
}

func queryJWKSRotationEvents(t *testing.T, secret, base string) []eventlog.Event {
	t.Helper()
	body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"notice","typ":"JwksRotated"}`))
	response := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	var events []eventlog.Event
	err := json.NewDecoder(response.Body).Decode(&events)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("JWKS rotation query node=%s status=%d decode=%v", base, response.StatusCode, err)
	}
	return events
}

func queryJWKSRotationEventsBrowser(t *testing.T, client *http.Client, base string) []eventlog.Event {
	t.Helper()
	body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"notice","typ":"JwksRotated"}`))
	response := do(t, client, http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	var events []eventlog.Event
	err := json.NewDecoder(response.Body).Decode(&events)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("JWKS rotation browser query node=%s status=%d decode=%v", base, response.StatusCode, err)
	}
	return events
}

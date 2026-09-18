// Package jwks verifies deployed signing-key rotation through its public JWKS endpoint.
package jwks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const jwksCacheLifetime = 5 * time.Minute

// TestAutomaticRotation observes a prepublished replacement become active
// while the old key remains available. Run it only against a fresh deployment
// configured with GOAUTHY_SIGNING_KEY_ROTATION_PERIOD=5m.
func TestAutomaticRotation(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION") != "1" {
		t.Skip("set GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1 and GOAUTHY_E2E_JWKS_ROTATION=1 against a fresh deployment with GOAUTHY_SIGNING_KEY_ROTATION_PERIOD=5m")
	}
	if os.Getenv("GOAUTHY_E2E_JWKS_ROTATION") != "1" {
		t.Skip("set GOAUTHY_E2E_JWKS_ROTATION=1 against a fresh deployment with GOAUTHY_SIGNING_KEY_ROTATION_PERIOD=5m")
	}
	baseURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	if baseURL == "" {
		t.Skip("set GOAUTHY_E2E_URL to run JWKS rotation E2E")
	}
	deadline := time.Now().Add(rotationWait(t))
	client := &http.Client{Timeout: 10 * time.Second}

	// The worker prepublishes before activation. It starts before HTTP serves,
	// but bounded polling also tolerates a server that comes up mid-step.
	before := waitFor(t, deadline, func() (snapshot, bool, error) {
		s, err := getJWKS(client, baseURL, "")
		return s, err == nil && len(s.Kids) == 2, err
	})
	oldActive := before.Kids[0]
	prepublished := before.Kids[1]
	if oldActive == "" || prepublished == "" || oldActive == prepublished {
		t.Fatalf("invalid initial JWKS: %#v", before)
	}
	if before.CacheControl != "public, max-age=300, must-revalidate" || before.ETag == "" {
		t.Fatalf("initial JWKS cache headers: %#v", before)
	}
	assertNotModified(t, client, baseURL, before.ETag)

	// max-age authorizes caches to retain the prepublished response; it does not
	// require the origin to remain unchanged. Poll its validator until activation.
	after := waitFor(t, deadline, func() (snapshot, bool, error) {
		s, err := getJWKS(client, baseURL, before.ETag)
		return s, err == nil && s.Status == http.StatusOK && s.Kids[0] != oldActive, err
	})
	if after.ETag == before.ETag {
		t.Fatal("JWKS ETag did not change after key activation")
	}
	if after.CacheControl != "public, max-age=300, must-revalidate" || after.Kids[0] != prepublished || !contains(after.Kids, oldActive) {
		t.Fatalf("activation did not preserve the prepublished/retiring JWKS overlap: before=%#v after=%#v", before, after)
	}
	assertNotModified(t, client, baseURL, after.ETag)
}

type snapshot struct {
	Status       int
	Kids         []string
	ETag         string
	CacheControl string
}

func getJWKS(client *http.Client, baseURL, etag string) (snapshot, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/oidc/jwks.json", nil)
	if err != nil {
		return snapshot{}, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	response, err := client.Do(req)
	if err != nil {
		return snapshot{}, err
	}
	defer response.Body.Close()
	s := snapshot{Status: response.StatusCode, ETag: response.Header.Get("ETag"), CacheControl: response.Header.Get("Cache-Control")}
	if response.StatusCode == http.StatusNotModified {
		return s, nil
	}
	if response.StatusCode != http.StatusOK {
		return s, fmt.Errorf("JWKS status %d", response.StatusCode)
	}
	var body struct {
		Keys []struct {
			KeyID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body); err != nil {
		return s, err
	}
	for _, key := range body.Keys {
		if key.KeyID == "" || contains(s.Kids, key.KeyID) {
			return s, fmt.Errorf("invalid JWKS key IDs")
		}
		s.Kids = append(s.Kids, key.KeyID)
	}
	if len(s.Kids) == 0 {
		return s, fmt.Errorf("empty JWKS")
	}
	return s, nil
}

func getJWKSMust(t *testing.T, client *http.Client, baseURL, etag string) snapshot {
	t.Helper()
	s, err := getJWKS(client, baseURL, etag)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func assertNotModified(t *testing.T, client *http.Client, baseURL, etag string) {
	t.Helper()
	s := getJWKSMust(t, client, baseURL, etag)
	if s.Status != http.StatusNotModified || s.ETag != etag || s.CacheControl != "public, max-age=300, must-revalidate" {
		t.Fatalf("conditional JWKS = %#v", s)
	}
}

func waitFor(t *testing.T, deadline time.Time, predicate func() (snapshot, bool, error)) snapshot {
	t.Helper()
	var last snapshot
	var lastErr error
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Until(deadline))
	defer timeout.Stop()
	for {
		s, ok, err := predicate()
		if err == nil {
			last = s
			if ok {
				return s
			}
		} else {
			lastErr = err
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("timed out waiting for JWKS transition: last=%#v err=%v", last, lastErr)
		}
	}
}

func rotationWait(t *testing.T) time.Duration {
	t.Helper()
	const defaultWait = 8 * time.Minute
	raw := os.Getenv("GOAUTHY_E2E_JWKS_ROTATION_TIMEOUT")
	if raw == "" {
		return defaultWait
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < jwksCacheLifetime+time.Minute || d > 20*time.Minute {
		t.Fatalf("GOAUTHY_E2E_JWKS_ROTATION_TIMEOUT must be between 6m and 20m: %q", raw)
	}
	return d
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

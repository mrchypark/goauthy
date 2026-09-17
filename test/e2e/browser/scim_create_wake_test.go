package browser

import (
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
)

func TestSCIMAdminCreateWake(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SCIM_CREATE_WAKE") != "1" {
		t.Skip("set GOAUTHY_E2E_SCIM_CREATE_WAKE=1 to run SCIM create wake E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	if primary == "" || secondary == "" || username == "" || password == "" {
		t.Fatal("SCIM create wake requires both URLs and browser credentials")
	}
	adminURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SCIM_ADMIN_URL"), "/")
	if adminURL == "" {
		t.Fatal("SCIM admin URL required")
	}
	client := newBrowserClient(t)
	_, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-wake", "scim-wake-nonce"), primary, secondary, username, password, "scim-wake")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	email, preferred := "scim-wake@goauthy.e2e", "scim-wake"
	body, _ := json.Marshal(map[string]any{"email": email, "language": "en", "roles": []string{}, "preferred_username": preferred, "user_expires": 4102444800, "tz": "Asia/Seoul"})
	r := do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	b, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d body=%s", r.StatusCode, b)
	}
	var created struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &created) != nil || created.ID == "" {
		t.Fatal("create response missing subject")
	}
	pollCtx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	pollClient := &http.Client{Timeout: 2 * time.Second}
	projectionExists := func() bool {
		request, err := http.NewRequestWithContext(pollCtx, http.MethodGet, adminURL+"/admin/state", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := pollClient.Do(request)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		var state struct {
			Users []struct {
				ExternalID string `json:"externalId"`
				UserName   string `json:"userName"`
				Active     bool   `json:"active"`
			} `json:"users"`
		}
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state) != nil {
			return false
		}
		matches := 0
		for _, u := range state.Users {
			if u.ExternalID == created.ID || u.UserName == email {
				matches++
				if u.ExternalID != created.ID || u.UserName != email || u.Active {
					t.Fatal("SCIM projection does not match the pending identity")
				}
			}
		}
		if matches > 1 {
			t.Fatal("duplicate SCIM remote subject or username")
		}
		return matches == 1
	}
	// Only the external fixture is polled; observed state, not elapsed time,
	// determines success. The 30s failure guard is below the 5-minute scan tick.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for !projectionExists() {
		select {
		case <-pollCtx.Done():
			t.Fatal("timed out waiting for SCIM create wake")
		case <-ticker.C:
		}
	}
	r = do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	r.Body.Close()
	if r.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("duplicate create status=%d", r.StatusCode)
	}
	if !projectionExists() {
		t.Fatal("duplicate request did not preserve the single remote projection")
	}
}

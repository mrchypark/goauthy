package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/oidc"
)

// TestDCRBackchannelLogoutAcrossPods exercises DCR-registered clients
// performing backchannel logout across HA pods.  A dynamically registered
// client with a backchannel_logout_uri receives logout tokens when the
// bootstrap user's session is terminated.
func TestDCRBackchannelLogoutAcrossPods(t *testing.T) {
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	globalToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL"), "/")
	if primary == "" || secondary == "" || tertiary == "" || globalToken == "" || username == "" || password == "" || sinkURL == "" {
		t.Skip("set GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, GOAUTHY_E2E_TERTIARY_URL, GOAUTHY_E2E_DCR_REGISTRATION_TOKEN, GOAUTHY_E2E_BROWSER_USERNAME, GOAUTHY_E2E_BROWSER_PASSWORD, and GOAUTHY_E2E_BACKCHANNEL_SINK_URL to run DCR backchannel E2E")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	const subject = "bootstrap-admin"
	originalURI := "http://goauthy-backchannel-sink.goauthy.svc.cluster.local:8081/backchannel"

	// Step 1: Register a password-capable DCR client with backchannel_logout_uri.
	registration := registerDCRPasswordBackchannelClient(t, client, primary, globalToken, originalURI)
	defer dcrBackchannelCleanup(t, client, registration)

	// Step 2: Verify the registration and URI were persisted across pods.
	assertDCRBackchannelMetadataURI(t, client, secondary, registration, originalURI)

	// Step 3: Issue a real dynamic-client password grant for the bootstrap subject.
	assertPasswordGrantToken(t, client, primary, registration.ClientID, registration.ClientSecret, username, password, http.StatusOK)

	// Step 4: Record the current sink events before triggering a supported subject logout.
	baseline := backchannelSinkEventCount(t, client, sinkURL)
	assertDCRSubjectLogout(t, primary, secondary, username, password, tertiary, subject)

	// Step 5: Verify a signed subject-only logout token for this DCR client.
	assertDCRBackchannelLogoutDelivered(t, client, sinkURL, baseline, primary, registration.ClientID, subject, originalURI, 10*time.Second)
}

func TestDCRPasswordBackchannelURIUpdateRemovalAcrossPods(t *testing.T) {
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	globalToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password := os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_BACKCHANNEL_SINK_URL"), "/")
	if primary == "" || secondary == "" || tertiary == "" || globalToken == "" || username == "" || password == "" || sinkURL == "" {
		t.Skip("set three E2E URLs, DCR registration token, browser username/password, and backchannel sink URL to run DCR password backchannel E2E")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	const subject = "bootstrap-admin"
	originalURI := "http://goauthy-backchannel-sink.goauthy.svc.cluster.local:8081/backchannel"
	updatedURI := "http://goauthy-backchannel-sink.goauthy.svc:8081/backchannel"
	configureBackchannelSink(t, client, sinkURL)
	registration := registerDCRPasswordBackchannelClient(t, client, primary, globalToken, originalURI)
	defer func() { dcrBackchannelCleanup(t, client, registration) }()

	assertDCRBackchannelMetadataURI(t, client, secondary, registration, originalURI)
	assertPasswordGrantToken(t, client, primary, registration.ClientID, registration.ClientSecret, username, password, http.StatusOK)

	registration = updateDCRPasswordBackchannelURI(t, client, secondary, registration, updatedURI)
	assertDCRBackchannelMetadataURI(t, client, tertiary, registration, updatedURI)
	baseline := backchannelSinkEventCount(t, client, sinkURL)
	assertDCRSubjectLogout(t, primary, secondary, username, password, tertiary, subject)
	assertDCRBackchannelLogoutDelivered(t, client, sinkURL, baseline, primary, registration.ClientID, subject, updatedURI, 10*time.Second)

	registration = updateDCRPasswordBackchannelURI(t, client, primary, registration, "")
	assertDCRBackchannelMetadataURI(t, client, secondary, registration, "")
	assertPasswordGrantToken(t, client, primary, registration.ClientID, registration.ClientSecret, username, password, http.StatusOK)
	baseline = backchannelSinkEventCount(t, client, sinkURL)
	assertDCRSubjectLogout(t, primary, secondary, username, password, secondary, subject)
	assertDCRBackchannelLogoutNotDelivered(t, client, sinkURL, baseline, primary, registration.ClientID, subject, 5*time.Second)
}

func registerDCRPasswordBackchannelClient(t *testing.T, client *http.Client, baseURL, globalToken, backchannelURI string) dcrRegistration {
	t.Helper()
	body, err := json.Marshal(struct {
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
		BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
	}{
		RedirectURIs:            []string{},
		GrantTypes:              []string{"password", "refresh_token"},
		ResponseTypes:           []string{},
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientName:              "GoAuthy DCR Password Backchannel E2E",
		BackchannelLogoutURI:    backchannelURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := dcrRequestWithKey(t, client, http.MethodPost, baseURL+"/oidc/register", body, globalToken, dcrBackchannelIdempotencyKey(t.Name(), "/oidc/register/password", body))
	defer response.Body.Close()
	var registration dcrRegistration
	if response.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&registration) != nil || registration.ClientID == "" || registration.ClientSecret == "" || registration.RegistrationAccessToken == "" || len(registration.GrantTypes) != 2 || registration.GrantTypes[0] != "password" || registration.GrantTypes[1] != "refresh_token" {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("DCR password backchannel create status=%d body=%q", response.StatusCode, body)
	}
	return registration
}

func updateDCRPasswordBackchannelURI(t *testing.T, client *http.Client, baseURL string, registration dcrRegistration, backchannelURI string) dcrRegistration {
	t.Helper()
	var uri any = backchannelURI
	if backchannelURI == "" {
		uri = nil
	}
	body, err := json.Marshal(map[string]any{
		"client_id":                  registration.ClientID,
		"redirect_uris":              []string{},
		"grant_types":                []string{"password", "refresh_token"},
		"response_types":             []string{},
		"token_endpoint_auth_method": "client_secret_basic",
		"client_name":                "GoAuthy DCR Password Backchannel E2E",
		"backchannel_logout_uri":     uri,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := dcrRequest(t, client, http.MethodPut, baseURL+"/oidc/register/"+registration.ClientID, body, registration.RegistrationAccessToken)
	defer response.Body.Close()
	var updated struct {
		dcrRegistration
		BackchannelLogoutURI string `json:"backchannel_logout_uri"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&updated) != nil || updated.ClientID != registration.ClientID || updated.ClientSecret == "" || updated.RegistrationAccessToken == "" {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("DCR password backchannel update status=%d body=%q", response.StatusCode, body)
	}
	if updated.BackchannelLogoutURI != backchannelURI {
		t.Fatalf("DCR password backchannel URI=%q want=%q", updated.BackchannelLogoutURI, backchannelURI)
	}
	return updated.dcrRegistration
}

func backchannelSinkEventCount(t *testing.T, client *http.Client, sinkURL string) int {
	t.Helper()
	count, err := readBackchannelSinkEventCount(client, sinkURL)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func configureBackchannelSink(t *testing.T, client *http.Client, sinkURL string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, sinkURL+"/control", strings.NewReader(`{"fail_first":0,"delay_first_ms":0,"success_status":204}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("backchannel sink control status=%d", response.StatusCode)
	}
}

type dcrBackchannelSinkEvent struct {
	Token  string `json:"token"`
	Status int    `json:"status"`
	Host   string `json:"host"`
}

func readBackchannelSinkEvents(client *http.Client, sinkURL string) ([]dcrBackchannelSinkEvent, error) {
	response, err := client.Get(sinkURL + "/events")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backchannel sink events status=%d", response.StatusCode)
	}
	var state struct {
		Events []dcrBackchannelSinkEvent `json:"events"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&state); err != nil {
		return nil, err
	}
	return state.Events, nil
}

func readBackchannelSinkEventCount(client *http.Client, sinkURL string) (int, error) {
	events, err := readBackchannelSinkEvents(client, sinkURL)
	if err != nil {
		return 0, err
	}
	return len(events), nil
}

func assertDCRSubjectLogout(t *testing.T, primary, secondary, username, password, base, subject string) {
	t.Helper()
	admin := managedBrowserClient(t)
	cookie := managedLogin(t, admin, primary, secondary, username, password)
	csrf, err := browser.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	response := managedDo(t, admin, http.MethodDelete, base+"/auth/v1/sessions/"+url.PathEscape(subject), nil, map[string]string{
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrf,
	})
	body := managedBody(t, response)
	if response.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("subject logout status=%d body=%q", response.StatusCode, body)
	}
}

func dcrBackchannelPublicJWKS(t *testing.T, client *http.Client, baseURL string) jose.JSONWebKeySet {
	t.Helper()
	response, err := client.Get(baseURL + "/oidc/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JWKS status=%d", response.StatusCode)
	}
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) == 0 {
		t.Fatal("public JWKS has no signing keys")
	}
	return keys
}

func assertDCRBackchannelLogoutDelivered(t *testing.T, client *http.Client, sinkURL string, baseline int, issuer, clientID, subject, expectedURI string, timeout time.Duration) {
	t.Helper()
	keys := dcrBackchannelPublicJWKS(t, client, issuer)
	expectedHost := dcrBackchannelURIHost(t, expectedURI)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := readBackchannelSinkEvents(client, sinkURL)
		if err == nil && baseline <= len(events) {
			for _, event := range events[baseline:] {
				if event.Status != http.StatusNoContent || event.Token == "" {
					continue
				}
				claims, verifyErr := oidc.VerifyLogoutToken(event.Token, keys, issuer, clientID, time.Now().UTC())
				if verifyErr == nil && claims.Subject == subject && claims.SessionID == "" && claims.JTI != "" && event.Host == expectedHost {
					return
				}
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for signed backchannel logout for client=%q subject=%q", clientID, subject)
		case <-ticker.C:
		}
	}
}

func dcrBackchannelURIHost(t *testing.T, rawURI string) string {
	t.Helper()
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Host == "" {
		t.Fatalf("invalid expected backchannel URI %q: %v", rawURI, err)
	}
	return parsed.Host
}

func assertDCRBackchannelLogoutNotDelivered(t *testing.T, client *http.Client, sinkURL string, baseline int, issuer, clientID, subject string, timeout time.Duration) {
	t.Helper()
	keys := dcrBackchannelPublicJWKS(t, client, issuer)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := readBackchannelSinkEvents(client, sinkURL)
		if err != nil {
			t.Fatal(err)
		}
		if baseline <= len(events) {
			for _, event := range events[baseline:] {
				if event.Token == "" {
					continue
				}
				claims, verifyErr := oidc.VerifyLogoutToken(event.Token, keys, issuer, clientID, time.Now().UTC())
				if verifyErr == nil && claims.Subject == subject && claims.SessionID == "" {
					t.Fatalf("backchannel logout delivered after URI removal for client=%q subject=%q", clientID, subject)
				}
			}
		}
		select {
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}

func assertDCRBackchannelMetadataURI(t *testing.T, client *http.Client, baseURL string, registration dcrRegistration, want string) {
	t.Helper()
	// The test sink exposes token/status data, not request host/path; the DCR
	// metadata response is the exact URI evidence for the alias update.
	response := dcrRequest(t, client, http.MethodGet, baseURL+"/oidc/register/"+registration.ClientID, nil, registration.RegistrationAccessToken)
	defer response.Body.Close()
	var metadata struct {
		BackchannelLogoutURI string `json:"backchannel_logout_uri"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&metadata) != nil || metadata.BackchannelLogoutURI != want {
		t.Fatalf("DCR backchannel metadata status=%d URI=%q want=%q", response.StatusCode, metadata.BackchannelLogoutURI, want)
	}
}

func dcrBackchannelCleanup(t *testing.T, client *http.Client, registration dcrRegistration) {
	t.Helper()
	if registration.RegistrationClientURI == "" || registration.RegistrationAccessToken == "" {
		return
	}
	request, err := http.NewRequest(http.MethodDelete, registration.RegistrationClientURI, nil)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", "Bearer "+registration.RegistrationAccessToken)
	response, err := client.Do(request)
	if err != nil {
		return
	}
	response.Body.Close()
}

func dcrBackchannelIdempotencyKey(testName, endpoint string, body []byte) string {
	h := sha256.New()
	for _, part := range []string{"goauthy-e2e-dcr-backchannel-v1", testName, endpoint, string(body)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

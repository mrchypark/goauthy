package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestAnonymousDynamicClientRegistrationAcrossPods exercises the deliberately
// narrow anonymous profile. The fixed rate window is long enough that this
// test never needs to wait for expiry.
func TestAnonymousDynamicClientRegistrationAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DCR_ANONYMOUS") != "true" {
		t.Skip("set GOAUTHY_E2E_DCR_ANONYMOUS=true to run anonymous DCR E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	if primary == "" || secondary == "" {
		t.Skip("set both E2E URLs to run anonymous DCR E2E")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	assertDCRDiscovery(t, client, primary)

	body := anonymousDCRBody(t, "anonymous-a")
	key := dcrIdempotencyKey(t.Name(), "/oidc/register", body)
	first, firstRaw := anonymousDCRRequest(t, client, primary+"/oidc/register", body, key, "198.51.100.10")
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("anonymous create status=%d body=%q", first.StatusCode, firstRaw)
	}
	var created dcrRegistration
	if err := json.Unmarshal(firstRaw, &created); err != nil {
		t.Fatal(err)
	}
	if created.ClientID == "" || created.RegistrationAccessToken == "" || created.RegistrationClientURI != primary+"/oidc/register/"+created.ClientID {
		t.Fatalf("anonymous create returned incomplete management credentials: %#v", created)
	}
	defer anonymousDCRCleanup(t, client, created)

	replay, replayRaw := anonymousDCRRequest(t, client, secondary+"/oidc/register", body, key, "198.51.100.10")
	if replay.StatusCode != http.StatusCreated || !bytes.Equal(replayRaw, firstRaw) {
		t.Fatalf("anonymous exact replay status=%d byte_identical=%t", replay.StatusCode, bytes.Equal(replayRaw, firstRaw))
	}

	limited, limitedRaw := anonymousDCRRequest(t, client, secondary+"/oidc/register", anonymousDCRBody(t, "anonymous-limited"), dcrIdempotencyKey(t.Name()+"/limited", "/oidc/register", body), "198.51.100.10")
	if limited.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("same canonical IP across pods status=%d body=%q, want 429", limited.StatusCode, limitedRaw)
	}

	different, differentRaw := anonymousDCRRequest(t, client, secondary+"/oidc/register", anonymousDCRBody(t, "anonymous-b"), dcrIdempotencyKey(t.Name()+"/different", "/oidc/register", body), "198.51.100.11")
	if different.StatusCode != http.StatusCreated {
		t.Fatalf("different canonical IP status=%d body=%q", different.StatusCode, differentRaw)
	}
	var other dcrRegistration
	if err := json.Unmarshal(differentRaw, &other); err != nil {
		t.Fatal(err)
	}
	if other.ClientID == "" || other.RegistrationAccessToken == "" {
		t.Fatalf("anonymous second create returned incomplete management credentials: %#v", other)
	}
	defer anonymousDCRCleanup(t, client, other)

	for _, registration := range []dcrRegistration{created, other} {
		response := dcrRequest(t, client, http.MethodGet, registration.RegistrationClientURI, nil, registration.RegistrationAccessToken)
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("per-registration management client_id=%q status=%d err=%v body=%q", registration.ClientID, response.StatusCode, err, payload)
		}
	}

	deviceBody := anonymousDeviceDCRBody(t, "anonymous-device")
	deviceKey := dcrIdempotencyKey(t.Name()+"/device", "/oidc/register", deviceBody)
	deviceResponse, deviceRaw := anonymousDCRRequest(t, client, secondary+"/oidc/register", deviceBody, deviceKey, "198.51.100.12")
	if deviceResponse.StatusCode != http.StatusCreated {
		t.Fatalf("anonymous device-only create status=%d body=%q", deviceResponse.StatusCode, deviceRaw)
	}
	var deviceClient dcrRegistration
	if err := json.Unmarshal(deviceRaw, &deviceClient); err != nil {
		t.Fatal(err)
	}
	if deviceClient.ClientID == "" || deviceClient.RegistrationAccessToken == "" || len(deviceClient.RedirectURIs) != 0 || len(deviceClient.ResponseTypes) != 0 || len(deviceClient.GrantTypes) != 1 || deviceClient.GrantTypes[0] != "urn:ietf:params:oauth:grant-type:device_code" || deviceClient.TokenEndpointAuthMethod != "none" {
		t.Fatalf("anonymous device-only metadata=%#v", deviceClient)
	}
	defer anonymousDCRCleanup(t, client, deviceClient)
	if !strings.Contains(" "+deviceClient.Scope+" ", " profile ") {
		t.Fatalf("anonymous device-only registration does not allow profile scope: %q", deviceClient.Scope)
	}

	deviceRequest := strings.NewReader(url.Values{"client_id": {deviceClient.ClientID}, "scope": {"profile"}}.Encode())
	deviceHTTP, err := http.NewRequest(http.MethodPost, secondary+"/oidc/device", deviceRequest)
	if err != nil {
		t.Fatal(err)
	}
	deviceHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deviceAuthorization, err := client.Do(deviceHTTP)
	if err != nil {
		t.Fatal(err)
	}
	devicePayload, err := io.ReadAll(io.LimitReader(deviceAuthorization.Body, 16<<10))
	deviceAuthorization.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if deviceAuthorization.StatusCode != http.StatusOK {
		t.Fatalf("anonymous device authorization status=%d body=%q", deviceAuthorization.StatusCode, devicePayload)
	}
	var grant struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
	if err := json.Unmarshal(devicePayload, &grant); err != nil {
		t.Fatal(err)
	}
	complete, err := url.Parse(grant.VerificationURIComplete)
	if err != nil || grant.DeviceCode == "" || grant.UserCode == "" || grant.VerificationURI == "" || grant.ExpiresIn < 1 || grant.Interval < 1 || complete.Path != "/oidc/device/verify" || complete.Query().Get("user_code") != grant.UserCode {
		t.Fatalf("invalid anonymous device authorization response=%#v parse_err=%v", grant, err)
	}
}

func anonymousDCRBody(t *testing.T, name string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"redirect_uris":              []string{"https://" + name + ".example.test/callback"},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"client_name":                name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func anonymousDeviceDCRBody(t *testing.T, name string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"redirect_uris":              []string{},
		"grant_types":                []string{"urn:ietf:params:oauth:grant-type:device_code"},
		"response_types":             []string{},
		"token_endpoint_auth_method": "none",
		"client_name":                name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func anonymousDCRRequest(t *testing.T, client *http.Client, endpoint string, body []byte, key, ip string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("Forwarded", "for="+ip)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, payload
}

func anonymousDCRCleanup(t *testing.T, client *http.Client, registration dcrRegistration) {
	t.Helper()
	if registration.RegistrationClientURI == "" || registration.RegistrationAccessToken == "" {
		return
	}
	response := dcrRequest(t, client, http.MethodDelete, registration.RegistrationClientURI, nil, registration.RegistrationAccessToken)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Errorf("anonymous DCR cleanup client_id=%q status=%d", registration.ClientID, response.StatusCode)
	}
}

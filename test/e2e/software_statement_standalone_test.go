package e2e

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const standaloneSoftwareStatement = "eyJhbGciOiJFZERTQSIsImtpZCI6InN0YXRlbWVudC0xIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2lkLmV4YW1wbGUudGVzdC9vaWRjL3JlZ2lzdGVyIiwiY2xpZW50X25hbWUiOiJBdHRlc3RlZCBTb2Z0d2FyZSIsImNsaWVudF91cmkiOiJodHRwczovL2F0dGVzdGVkLmV4YW1wbGUudGVzdCIsImNvbnRhY3RzIjpbInNlY3VyaXR5QGF0dGVzdGVkLmV4YW1wbGUudGVzdCJdLCJleHAiOjQxMDI0NDQ4MDAsImdyYW50X3R5cGVzIjpbImF1dGhvcml6YXRpb25fY29kZSJdLCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6Imh0dHBzOi8vcHVibGlzaGVyLmV4YW1wbGUudGVzdCIsInJlZGlyZWN0X3VyaXMiOlsiaHR0cHM6Ly9hdHRlc3RlZC5leGFtcGxlLnRlc3QvY2FsbGJhY2siXSwicmVzcG9uc2VfdHlwZXMiOlsiY29kZSJdLCJzb2Z0d2FyZV9pZCI6InNvZnR3YXJlLXN0YW5kYWxvbmUtdjEiLCJ0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZCI6Im5vbmUifQ.VlsU32qxACyViWunWR4iHKZVWkPqrbNd7uVe-5ivQ9_fNNuynuGIKrReSAVHD1sEmJ0-g7KAjFq-vK48RdBfDA"

const standaloneSoftwareStatementIssuer = "https://publisher.example.test"
const standaloneSoftwareStatementAudience = "https://id.example.test/oidc/register"
const standaloneDCRToken = "standalone-dcr-registration-token-0123456789"

type standaloneSoftwareRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientURI               string   `json:"client_uri"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	ClientName              string   `json:"client_name"`
	Contacts                []string `json:"contacts"`
	SoftwareStatement       string   `json:"software_statement"`
}

// TestStandaloneSoftwareStatement verifies the deployed RFC 7591 route with
// a static trusted issuer/JWKS fixture. The script runs this test before and
// after a cold restart; the fixed idempotency key therefore proves persistence
// by requiring the exact original response on replay and the exact JWT on GET.
func TestStandaloneSoftwareStatement(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SOFTWARE_STATEMENT_STANDALONE") != "1" {
		t.Skip("set GOAUTHY_E2E_SOFTWARE_STATEMENT_STANDALONE=1 to run standalone software-statement E2E")
	}
	baseURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	if baseURL == "" {
		t.Fatal("GOAUTHY_E2E_URL is required")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	body := `{"redirect_uris":["https://self.example.test/callback"],"grant_types":["client_credentials"],"response_types":["token"],"token_endpoint_auth_method":"client_secret_basic","client_name":"Self Asserted","software_statement":"` + standaloneSoftwareStatement + `"}`
	first := postStandaloneRegistration(t, client, baseURL, standaloneDCRToken, "software-statement-standalone", body)
	if first.SoftwareStatement != standaloneSoftwareStatement || first.ClientName != "Attested Software" || first.ClientURI != "https://attested.example.test" || !reflect.DeepEqual(first.RedirectURIs, []string{"https://attested.example.test/callback"}) || !reflect.DeepEqual(first.GrantTypes, []string{"authorization_code"}) || !reflect.DeepEqual(first.ResponseTypes, []string{"code"}) || first.TokenEndpointAuthMethod != "none" || !reflect.DeepEqual(first.Contacts, []string{"security@attested.example.test"}) {
		t.Fatalf("software statement did not take metadata precedence: %#v", first)
	}
	if first.ClientID == "" || first.RegistrationAccessToken == "" || first.RegistrationClientURI == "" {
		t.Fatalf("registration response missing persistence handles: %#v", first)
	}

	get := getStandaloneRegistration(t, client, first.RegistrationClientURI, first.RegistrationAccessToken)
	if get.SoftwareStatement != standaloneSoftwareStatement || get.ClientID != first.ClientID || get.ClientName != first.ClientName || get.ClientURI != first.ClientURI || !reflect.DeepEqual(get.RedirectURIs, first.RedirectURIs) || !reflect.DeepEqual(get.Contacts, first.Contacts) {
		t.Fatalf("GET registration did not persist exact statement metadata: %#v want %#v", get, first)
	}

	assertStandaloneRegistrationError(t, client, baseURL, standaloneDCRToken, "software-statement-invalid-signature", strings.Replace(standaloneSoftwareStatement, ".VlsU", ".WlsU", 1), http.StatusBadRequest, "invalid_software_statement")
	assertStandaloneRegistrationError(t, client, baseURL, standaloneDCRToken, "software-statement-invalid-issuer", standaloneSignedStatement(t, "https://unknown.example.test", standaloneSoftwareStatementAudience), http.StatusBadRequest, "unapproved_software_statement")
	assertStandaloneRegistrationError(t, client, baseURL, standaloneDCRToken, "software-statement-invalid-audience", standaloneSignedStatement(t, standaloneSoftwareStatementIssuer, "https://wrong.example.test/register"), http.StatusBadRequest, "invalid_software_statement")
	assertStandaloneRegistrationError(t, client, baseURL, "", "software-statement-anonymous", standaloneSoftwareStatement, http.StatusUnauthorized, "")
}

func postStandaloneRegistration(t *testing.T, client *http.Client, baseURL, bearer, idempotencyKey, body string) standaloneSoftwareRegistration {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/register", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("software statement POST status=%d body=%q", response.StatusCode, data)
	}
	var registration standaloneSoftwareRegistration
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

func getStandaloneRegistration(t *testing.T, client *http.Client, endpoint, bearer string) standaloneSoftwareRegistration {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("software statement GET status=%d body=%q", response.StatusCode, data)
	}
	var registration standaloneSoftwareRegistration
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

func assertStandaloneRegistrationError(t *testing.T, client *http.Client, baseURL, bearer, idempotencyKey, statement string, wantStatus int, want string) {
	t.Helper()
	body := `{"redirect_uris":["https://negative.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","software_statement":"` + statement + `"}`
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/register", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("software statement negative status=%d want=%d body=%q", response.StatusCode, wantStatus, data)
	}
	if want == "" {
		return
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if want != "" && payload.Error != want {
		t.Fatalf("software statement negative error=%q want %q", payload.Error, want)
	}
}

func standaloneSignedStatement(t *testing.T, issuer, audience string) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: private, KeyID: "statement-1"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": issuer, "aud": audience, "iat": int64(1700000000), "exp": int64(4102444800),
		"software_id": "software-standalone-v1", "client_name": "Attested Software",
		"redirect_uris": []string{"https://attested.example.test/callback"}, "grant_types": []string{"authorization_code"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

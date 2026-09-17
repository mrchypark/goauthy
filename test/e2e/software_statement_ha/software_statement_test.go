package software_statement_ha

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	statementIssuer = "https://publisher.example.test"
	softwareID      = "software-ha-v1"
	dcrToken        = "ha-software-statement-registration-token-0123456789"
)

type registration struct {
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

func TestSoftwareStatementHA(t *testing.T) {
	urls := strings.Split(strings.TrimSpace(os.Getenv("GOAUTHY_E2E_SOFTWARE_STATEMENT_URLS")), ",")
	if len(urls) == 1 && urls[0] == "" {
		t.Skip("set GOAUTHY_E2E_SOFTWARE_STATEMENT_URLS to three comma-separated pod URLs")
	}
	if len(urls) != 3 {
		t.Fatalf("software-statement URLs=%d, want exactly 3", len(urls))
	}
	for i := range urls {
		urls[i] = strings.TrimRight(strings.TrimSpace(urls[i]), "/")
		if urls[i] == "" {
			t.Fatal("software-statement URL is empty")
		}
	}
	audience := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SOFTWARE_STATEMENT_ISSUER"), "/") + "/oidc/register"
	if strings.HasPrefix(audience, "/") {
		t.Fatal("GOAUTHY_E2E_SOFTWARE_STATEMENT_ISSUER is required")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	statement := signedStatement(t, statementIssuer, audience)
	body := registrationBody(t, statement)
	phase := os.Getenv("GOAUTHY_E2E_SOFTWARE_STATEMENT_PHASE")
	created, raw := createRegistration(t, client, urls[0], body, "software-statement-ha-valid")
	if phase == "post-restart" {
		path := os.Getenv("GOAUTHY_E2E_SOFTWARE_STATEMENT_STATE_FILE")
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, want) {
			t.Fatalf("idempotent response changed after pod replacement")
		}
	} else {
		path := os.Getenv("GOAUTHY_E2E_SOFTWARE_STATEMENT_STATE_FILE")
		if path == "" {
			t.Fatal("GOAUTHY_E2E_SOFTWARE_STATEMENT_STATE_FILE is required")
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	assertStatementMetadata(t, created, statement)
	for _, base := range urls[1:] {
		got := getRegistration(t, client, base+"/oidc/register/"+created.ClientID, created.RegistrationAccessToken)
		assertSameRegistration(t, got, created)
	}

	for i, base := range urls {
		invalidSignature := corruptSignature(statement)
		assertStatementError(t, client, base, "software-statement-ha-invalid-signature-"+string(rune('0'+i)), invalidSignature, "invalid_software_statement")
		unknownIssuer := signedStatement(t, "https://unknown.example.test", audience)
		assertStatementError(t, client, base, "software-statement-ha-invalid-issuer-"+string(rune('0'+i)), unknownIssuer, "unapproved_software_statement")
		wrongAudience := signedStatement(t, statementIssuer, "https://wrong.example.test/oidc/register")
		assertStatementError(t, client, base, "software-statement-ha-invalid-audience-"+string(rune('0'+i)), wrongAudience, "invalid_software_statement")
	}
	t.Logf("software_statement trusted config, exact metadata/JWT persistence, and negatives passed across 3 pods (phase=%s)", phase)
}

func registrationBody(t *testing.T, statement string) []byte {
	t.Helper()
	value := map[string]any{
		"redirect_uris": []string{"https://self.example.test/callback"},
		"grant_types":   []string{"client_credentials"}, "response_types": []string{"token"},
		"token_endpoint_auth_method": "client_secret_basic", "client_name": "Self Asserted", "software_statement": statement,
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signedStatement(t *testing.T, issuer, audience string) string {
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
		"iss": issuer, "aud": audience, "iat": int64(1700000000), "exp": int64(4102444800), "software_id": softwareID,
		"client_name": "Attested Software", "client_uri": "https://attested.example.test",
		"contacts": []string{"security@attested.example.test"}, "redirect_uris": []string{"https://attested.example.test/callback"},
		"grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func corruptSignature(token string) string {
	parts := strings.Split(token, ".")
	first := parts[2][0]
	if first == 'A' {
		first = 'B'
	} else {
		first = 'A'
	}
	parts[2] = string(first) + parts[2][1:]
	return strings.Join(parts, ".")
}

func createRegistration(t *testing.T, client *http.Client, base string, body []byte, idempotency string) (registration, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, base+"/oidc/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+dcrToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotency)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("software statement POST status=%d body=%q", response.StatusCode, raw)
	}
	var value registration
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value, raw
}

func getRegistration(t *testing.T, client *http.Client, endpoint, token string) registration {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("software statement GET status=%d body=%q", response.StatusCode, data)
	}
	var value registration
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertStatementError(t *testing.T, client *http.Client, base, idempotency, statement, want string) {
	t.Helper()
	body := registrationBody(t, statement)
	request, err := http.NewRequest(http.MethodPost, base+"/oidc/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+dcrToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotency)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("software statement negative status=%d body=%q", response.StatusCode, data)
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &payload); err != nil || payload.Error != want {
		t.Fatalf("software statement negative error=%q want %q body=%q", payload.Error, want, data)
	}
}

func assertStatementMetadata(t *testing.T, value registration, statement string) {
	t.Helper()
	if value.ClientID == "" || value.RegistrationAccessToken == "" || value.RegistrationClientURI == "" || value.SoftwareStatement != statement || value.ClientName != "Attested Software" || value.ClientURI != "https://attested.example.test" || strings.Join(value.RedirectURIs, ",") != "https://attested.example.test/callback" || strings.Join(value.GrantTypes, ",") != "authorization_code" || strings.Join(value.ResponseTypes, ",") != "code" || value.TokenEndpointAuthMethod != "none" || strings.Join(value.Contacts, ",") != "security@attested.example.test" {
		t.Fatalf("software statement metadata precedence failed: %#v", value)
	}
}

func assertSameRegistration(t *testing.T, got, want registration) {
	t.Helper()
	// GET intentionally redacts the write-only registration access token and
	// registration endpoint; compare the persisted identity and metadata.
	if got.ClientID != want.ClientID || got.ClientURI != want.ClientURI || got.ClientName != want.ClientName || got.SoftwareStatement != want.SoftwareStatement || strings.Join(got.RedirectURIs, "\x00") != strings.Join(want.RedirectURIs, "\x00") || strings.Join(got.GrantTypes, "\x00") != strings.Join(want.GrantTypes, "\x00") || strings.Join(got.ResponseTypes, "\x00") != strings.Join(want.ResponseTypes, "\x00") || strings.Join(got.Contacts, "\x00") != strings.Join(want.Contacts, "\x00") || got.TokenEndpointAuthMethod != want.TokenEndpointAuthMethod {
		t.Fatalf("cross-pod registration mismatch: got=%#v want=%#v", got, want)
	}
}

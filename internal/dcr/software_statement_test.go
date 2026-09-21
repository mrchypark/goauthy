package dcr

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func testSoftwareStatement(t *testing.T, claims map[string]any) (string, jose.JSONWebKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	key := jose.JSONWebKey{Key: private.Public(), KeyID: "statement-1", Algorithm: string(jose.EdDSA), Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: private, KeyID: "statement-1"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token, key
}

func TestSoftwareStatementVerifyAndMerge(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	token, key := testSoftwareStatement(t, map[string]any{
		"iss": "https://publisher.example.test", "aud": "https://id.example.test/oidc/register",
		"exp": now.Add(time.Hour).Unix(), "client_name": "Attested", "redirect_uris": []string{"https://attested.example.test/callback"},
	})
	policy, err := newSoftwareStatementPolicy(SoftwareStatementConfig{Now: func() time.Time { return now }, Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", Audience: "https://id.example.test/oidc/register", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}}}})
	if err != nil {
		t.Fatal(err)
	}
	request := registrationRequest{ClientName: "self-asserted", RedirectURIs: []string{"https://self.example.test/callback"}}
	merged, statement, err := policy.merge(token, request)
	if err != nil {
		t.Fatal(err)
	}
	if statement != token || merged.ClientName != "Attested" || len(merged.RedirectURIs) != 1 || merged.RedirectURIs[0] != "https://attested.example.test/callback" {
		t.Fatalf("statement merge=%+v statement=%q", merged, statement)
	}
}

func TestSoftwareStatementOptionalAudience(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	token, key := testSoftwareStatement(t, map[string]any{
		"iss": "https://publisher.example.test", "exp": now.Add(time.Hour).Unix(), "client_name": "Attested",
	})
	config := SoftwareStatementConfig{Now: func() time.Time { return now }, Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}}}}
	if _, err := config.CanonicalDigest(); err != nil {
		t.Fatal(err)
	}
	policy, err := newSoftwareStatementPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	merged, statement, err := policy.merge(token, registrationRequest{})
	if err != nil || statement != token || merged.ClientName != "Attested" {
		t.Fatalf("audience-omitted statement rejected: merged=%+v statement=%q err=%v", merged, statement, err)
	}
	withAudience, _ := testSoftwareStatement(t, map[string]any{
		"iss": "https://publisher.example.test", "aud": "https://unexpected.example.test", "exp": now.Add(time.Hour).Unix(),
	})
	if _, _, err := policy.merge(withAudience, registrationRequest{}); !errors.Is(err, errInvalidSoftwareStatement) {
		t.Fatalf("unconfigured audience accepted: %v", err)
	}
}

func TestSoftwareStatementCanonicalDigestIgnoresOrdering(t *testing.T) {
	t.Parallel()
	_, first := testSoftwareStatement(t, map[string]any{"iss": "https://publisher.example.test"})
	_, second := testSoftwareStatement(t, map[string]any{"iss": "https://publisher.example.test"})
	first.KeyID, second.KeyID = "b", "a"
	configA := SoftwareStatementConfig{Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", Audience: "https://id.example.test/oidc/register", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{first, second}}}}}
	configB := SoftwareStatementConfig{Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", Audience: "https://id.example.test/oidc/register", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{second, first}}}}}
	digestA, err := configA.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := configB.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if digestA != digestB {
		t.Fatalf("ordering changed digest: %q != %q", digestA, digestB)
	}
}

func TestSoftwareStatementRejectsUnapprovedAndInvalid(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	token, key := testSoftwareStatement(t, map[string]any{"iss": "https://publisher.example.test", "exp": now.Add(time.Hour).Unix()})
	policy, err := newSoftwareStatementPolicy(SoftwareStatementConfig{Now: func() time.Time { return now }, Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", Audience: "https://id.example.test/oidc/register", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := policy.merge(token, registrationRequest{}); !errors.Is(err, errInvalidSoftwareStatement) {
		t.Fatalf("wrong audience error=%v", err)
	}
	unknown, _, err := testSoftwareStatementWithIssuer(t, "https://unknown.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := policy.merge(unknown, registrationRequest{}); !errors.Is(err, errUnapprovedSoftwareStatement) {
		t.Fatalf("unknown issuer error=%v", err)
	}
	if _, _, err := policy.merge(token+"x", registrationRequest{}); !errors.Is(err, errInvalidSoftwareStatement) {
		t.Fatalf("bad signature error=%v", err)
	}
}

func testSoftwareStatementWithIssuer(t *testing.T, issuer string, now time.Time) (string, jose.JSONWebKey, error) {
	token, key := testSoftwareStatement(t, map[string]any{"iss": issuer, "exp": now.Add(time.Hour).Unix()})
	return token, key, nil
}

func TestLoadSoftwareStatementConfigStrict(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/trust.json"
	key := jose.JSONWebKey{Key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public(), KeyID: "k", Algorithm: string(jose.EdDSA), Use: "sig"}
	body, err := json.Marshal(SoftwareStatementConfig{Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", Audience: "https://id.example.test/oidc/register", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSoftwareStatementConfig(path)
	if err != nil || len(loaded.Issuers) != 1 {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err := os.WriteFile(path, []byte(`{"issuers":[{"issuer":"https://publisher.example.test","audience":"https://id.example.test/oidc/register","jwks":{"keys":[{"kid":"k","use":"sig","alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"AA"}],"keys":[]}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSoftwareStatementConfig(path); err == nil {
		t.Fatal("nested duplicate trust member accepted")
	}
	for name, raw := range map[string]string{
		"top-level alias":           `{"ISSUERS":[]}`,
		"top-level case collision":  `{"issuers":[],"ISSUERS":[]}`,
		"issuer alias":              `{"issuers":[{"ISSUER":"https://publisher.example.test"}]}`,
		"nested jwks alias":         `{"issuers":[{"issuer":"https://publisher.example.test","JWKS":{"keys":[]}}]}`,
		"nested JWK case collision": `{"issuers":[{"issuer":"https://publisher.example.test","jwks":{"keys":[{"kid":"one","KID":"two"}]}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSoftwareStatementConfig(path); err == nil {
				t.Fatal("case-variant trust member accepted")
			}
		})
	}
}

func TestSoftwareStatementHTTPResponseAndIdempotency(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	token, key := testSoftwareStatement(t, map[string]any{"iss": "https://publisher.example.test", "aud": "https://id.example.test/oidc/register", "exp": now.Add(time.Hour).Unix(), "client_name": "Attested", "redirect_uris": []string{"https://attested.example.test/callback"}, "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
	config := SoftwareStatementConfig{Now: func() time.Time { return now }, Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", Audience: "https://id.example.test/oidc/register", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}}}}
	db := openTestDB(t, "dcr-statement-http-test")
	h, err := NewHandler(NewStore(db, Config{Keyring: testEnvelopeKeyring(t), Now: func() time.Time { return now }}), "https://id.example.test", testGlobalToken, HandlerConfig{SoftwareStatements: config})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"redirect_uris":["https://self.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Self","software_statement":"` + token + `"}`
	request := httptest.NewRequest(http.MethodPost, registrationPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testGlobalToken)
	request.Header.Set("Idempotency-Key", "statement-http")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"software_statement":"`+token+`"`) || !strings.Contains(response.Body.String(), `"client_name":"Attested"`) || strings.Contains(response.Body.String(), "self.example.test") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	replayRequest := httptest.NewRequest(http.MethodPost, registrationPath, strings.NewReader(body))
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.Header.Set("Authorization", "Bearer "+testGlobalToken)
	replayRequest.Header.Set("Idempotency-Key", "statement-http")
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusCreated || replay.Body.String() != response.Body.String() {
		t.Fatalf("replay status=%d body=%s want=%s", replay.Code, replay.Body.String(), response.Body.String())
	}
}

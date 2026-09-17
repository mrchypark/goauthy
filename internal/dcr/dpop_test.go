package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/ory/fosite"
)

func dpopRegistrationBody(clientID, name string, value string) string {
	prefix := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"` + name + `"`
	if clientID != "" {
		prefix = `{"client_id":"` + clientID + `",` + strings.TrimPrefix(prefix, "{")
	}
	if value != "" {
		prefix += `,"dpop_bound_access_tokens":` + value
	}
	return prefix + `}`
}

func TestDPoPBoundAccessTokensHTTPRoundTripAndReplacement(t *testing.T) {
	h := testHandler(t, testGlobalToken)
	created := httptest.NewRecorder()
	h.ServeHTTP(created, requestWithKey(http.MethodPost, registrationPath, dpopRegistrationBody("", "DPoP RP", "true"), testGlobalToken, "dpop-roundtrip"))
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"dpop_bound_access_tokens":true`) {
		t.Fatalf("create status=%d", created.Code)
	}
	var registration registrationResponse
	if err := json.Unmarshal(created.Body.Bytes(), &registration); err != nil || !registration.DPoPBoundAccessTokens {
		t.Fatalf("created dpop=%t err=%v", registration.DPoPBoundAccessTokens, err)
	}

	get := httptest.NewRecorder()
	h.ServeHTTP(get, request(http.MethodGet, registrationPath+"/"+registration.ClientID, "", registration.RegistrationAccessToken))
	var loaded registrationResponse
	if get.Code != http.StatusOK || json.Unmarshal(get.Body.Bytes(), &loaded) != nil || !loaded.DPoPBoundAccessTokens {
		t.Fatalf("get status=%d dpop=%t", get.Code, loaded.DPoPBoundAccessTokens)
	}

	updated := httptest.NewRecorder()
	h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+registration.ClientID, dpopRegistrationBody(registration.ClientID, "DPoP RP", "true"), registration.RegistrationAccessToken))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d", updated.Code)
	}
	var replacement registrationResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &replacement); err != nil || !replacement.DPoPBoundAccessTokens {
		t.Fatalf("updated dpop=%t err=%v", replacement.DPoPBoundAccessTokens, err)
	}
	omitted := httptest.NewRecorder()
	h.ServeHTTP(omitted, request(http.MethodPut, registrationPath+"/"+registration.ClientID, dpopRegistrationBody(registration.ClientID, "DPoP RP", ""), replacement.RegistrationAccessToken))
	if omitted.Code != http.StatusOK {
		t.Fatalf("omitted update status=%d", omitted.Code)
	}
	var omittedRegistration registrationResponse
	if err := json.Unmarshal(omitted.Body.Bytes(), &omittedRegistration); err != nil || omittedRegistration.DPoPBoundAccessTokens {
		t.Fatalf("omitted update dpop=%t err=%v", omittedRegistration.DPoPBoundAccessTokens, err)
	}
	read := httptest.NewRecorder()
	h.ServeHTTP(read, request(http.MethodGet, registrationPath+"/"+registration.ClientID, "", omittedRegistration.RegistrationAccessToken))
	var persisted registrationResponse
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &persisted) != nil || persisted.DPoPBoundAccessTokens {
		t.Fatalf("persisted read status=%d dpop=%t", read.Code, persisted.DPoPBoundAccessTokens)
	}
}

func TestDPoPBoundAccessTokensDefaultsFalseAndStoreNotFound(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("dpop-default", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if created.DPoPBoundAccessTokens {
		t.Fatal("omitted DPoP binding defaulted true")
	}
	if got, err := store.DPoPBoundAccessTokens(ctx, created.ClientID); err != nil || got {
		t.Fatalf("stored default=%t err=%v", got, err)
	}
	if _, err := store.DPoPBoundAccessTokens(ctx, "missing-dpop-client"); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("missing client err=%v", err)
	}
}

func TestDPoPBoundAccessTokensStrictHTTPBool(t *testing.T) {
	h := testHandler(t, testGlobalToken)
	for _, value := range []string{`"true"`, `1`, `null`} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, dpopRegistrationBody("", "Strict DPoP", value), testGlobalToken, "dpop-strict-"+value))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("value %s status=%d body=%s", value, response.Code, response.Body.String())
		}
	}
}

func TestDPoPBoundAccessTokensAnonymousCreate(t *testing.T) {
	h := testAnonymousHandler(t, time.Minute)
	req := requestWithKey(http.MethodPost, registrationPath, dpopRegistrationBody("", "Anonymous DPoP", "true"), "", "dpop-anonymous")
	req = req.WithContext(browser.ContextWithPeerIP(context.Background(), "198.51.100.77"))
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	var registration registrationResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &registration) != nil || !registration.DPoPBoundAccessTokens {
		t.Fatalf("anonymous status=%d dpop=%t", response.Code, registration.DPoPBoundAccessTokens)
	}
}

func TestDPoPBoundAccessTokensSoftwareStatementTakesPrecedence(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	token, key := testSoftwareStatement(t, map[string]any{
		"iss": "https://publisher.example.test", "aud": "https://id.example.test/oidc/register",
		"exp": now.Add(time.Hour).Unix(), "client_name": "Attested", "dpop_bound_access_tokens": true,
	})
	h := testHandlerWithHandlerConfig(t, testGlobalToken, Config{Now: func() time.Time { return now }}, HandlerConfig{SoftwareStatements: SoftwareStatementConfig{
		Now: func() time.Time { return now }, Issuers: []SoftwareStatementIssuer{{Issuer: "https://publisher.example.test", Audience: "https://id.example.test/oidc/register", JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}}},
	}})
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Self","dpop_bound_access_tokens":false,"software_statement":"` + token + `"}`
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, "dpop-statement"))
	var registration registrationResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &registration) != nil || !registration.DPoPBoundAccessTokens {
		t.Fatalf("statement status=%d dpop=%t", response.Code, registration.DPoPBoundAccessTokens)
	}
}

func TestDPoPBoundAccessTokensIdempotencyDistinguishesValue(t *testing.T) {
	h := testHandler(t, testGlobalToken)
	first := httptest.NewRecorder()
	h.ServeHTTP(first, requestWithKey(http.MethodPost, registrationPath, dpopRegistrationBody("", "Idempotent DPoP", "false"), testGlobalToken, "dpop-same-key"))
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d", first.Code)
	}
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, requestWithKey(http.MethodPost, registrationPath, dpopRegistrationBody("", "Idempotent DPoP", "false"), testGlobalToken, "dpop-same-key"))
	if replay.Code != http.StatusCreated {
		t.Fatalf("same-value replay status=%d", replay.Code)
	}
	second := httptest.NewRecorder()
	h.ServeHTTP(second, requestWithKey(http.MethodPost, registrationPath, dpopRegistrationBody("", "Idempotent DPoP", "true"), testGlobalToken, "dpop-same-key"))
	if second.Code != http.StatusUnprocessableEntity {
		t.Fatalf("changed value status=%d", second.Code)
	}
}

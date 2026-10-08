package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/saas"
)

const useGrantResource = "https://goauthy.connections.local.test"

const (
	isolation113SetupConfigReady        = "config_ready"
	isolation113SetupInitialLogin       = "initial_login_complete"
	isolation113SetupProviderCreated    = "provider_created"
	isolation113SetupCollectionCreated  = "collection_created"
	isolation113SetupConnectionCreated  = "connection_created"
	isolation113SetupKeyBound           = "api_key_bound"
	isolation113SetupConsumerCreated    = "consumer_created"
	isolation113SetupGrantCreated       = "grant_created"
	isolation113SetupScopeReady         = "invoke_scope_ready"
	isolation113SetupInvokeTokenIssued  = "invoke_token_issued"
	isolation113SetupInvokeChecksPassed = "invoke_prechecks_complete"
	isolation113SetupDiagnosticEntered  = "diagnostic_entered"
)

func TestConnectionUseGrantLive(t *testing.T) {
	isolation113Diagnostic := os.Getenv("GOAUTHY_E2E_USE_GRANTS") == "1" &&
		os.Getenv("GOAUTHY_E2E_GRANT_INVOKE") == "1" &&
		os.Getenv("GOAUTHY_E2E_ISOLATION113_FIXTURE_URL") != ""
	if os.Getenv("GOAUTHY_E2E_USE_GRANTS") != "1" {
		t.Skip("set GOAUTHY_E2E_USE_GRANTS=1 to run connection-use grant E2E")
	}
	connectorID := uniqueCollectionID(t)
	primary, secondary, user, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupConfigReady)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "connection-use-grant")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupInitialLogin)
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	prefix := "Bearer "
	if os.Getenv("GOAUTHY_E2E_RAW_AUTHORIZATION") == "1" {
		prefix = ""
	}
	apiURL := "https://api.example.com/account"
	apiKeyValue := "e2e-bound-api-key"
	var apiOperations any = []map[string]any{{"id": "account", "url": apiURL, "response_fields": map[string]string{"id": "string"}}}
	if fixtureURL := os.Getenv("GOAUTHY_E2E_ISOLATION113_FIXTURE_URL"); fixtureURL != "" {
		operations, err := isolation113FixtureOperations(connectorID, prefix, fixtureURL)
		if err != nil {
			t.Fatalf("invalid isolation fixture operation definition: %v", err)
		}
		apiOperations = operations
		apiKeyValue = os.Getenv("GOAUTHY_E2E_ISOLATION113_API_KEY")
		if apiKeyValue == "" {
			t.Fatal("GOAUTHY_E2E_ISOLATION113_API_KEY is required with the local fixture")
		}
	}
	providerConfig := map[string]any{"id": connectorID, "name": "Use grant provider", "kind": "api_key", "enabled": true, "callback_uri": "", "scopes": []string{}, "connector": map[string]any{"id": connectorID, "header": "Authorization", "prefix": prefix, "operations": apiOperations}}
	providerJSON, err := json.Marshal(providerConfig)
	if err != nil {
		t.Fatal("encode API-key provider configuration")
	}
	providerBody := string(providerJSON)
	if os.Getenv("GOAUTHY_E2E_CONDUCTOR_DELIVERY_PROJECT_DIR") != "" {
		if prefix != "" {
			t.Fatal("Conductor delivery fixture requires raw Authorization")
		}
		providerBody = strings.Replace(providerBody, "https://api.example.com/account", "https://openapi.gowid.com/v2/expense-statements", 1)
	}
	provider := do(t, client, http.MethodPost, primary+"/auth/v1/saas/providers", strings.NewReader(providerBody), headers)
	provider.Body.Close()
	if provider.StatusCode != http.StatusCreated {
		t.Fatalf("provider create status=%d", provider.StatusCode)
	}
	t.Cleanup(func() {
		r := do(t, client, http.MethodDelete, primary+"/auth/v1/saas/providers/"+connectorID, nil, sessionHeader(headers, "If-Match", `"1"`))
		r.Body.Close()
	})
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupProviderCreated)

	collectionID := uniqueCollectionID(t)
	collectionBody := `{"id":"` + collectionID + `","name":"Use grant E2E","auth_method":"api_key","enabled":true,"fields":[],"provider_ids":["` + connectorID + `"]}`
	collection := do(t, client, http.MethodPost, primary+"/auth/v1/auth-collections", strings.NewReader(collectionBody), headers)
	_, collectionRevision := readCollection(t, collection, http.StatusCreated)
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupCollectionCreated)
	connection := do(t, client, http.MethodPost, primary+"/auth/v1/account/connections/"+collectionID, strings.NewReader(`{"definition_revision":1,"metadata":{}}`), headers)
	connectionDoc, connectionRevision := readCollection(t, connection, http.StatusCreated)
	connectionID, ok := connectionDoc["id"].(string)
	if !ok || connectionID == "" {
		t.Fatal("connection ID missing")
	}
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupConnectionCreated)
	connectionBase := primary + "/auth/v1/account/connections/" + collectionID + "/" + connectionID
	connector := do(t, client, http.MethodGet, connectionBase+"/api-key/connector", nil, headers)
	var connectorDoc struct {
		Digest string `json:"digest"`
		Prefix string `json:"prefix"`
	}
	if connector.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(connector.Body, 4096)).Decode(&connectorDoc) != nil || connectorDoc.Digest == "" {
		connector.Body.Close()
		t.Fatalf("connector metadata status=%d", connector.StatusCode)
	}
	connector.Body.Close()
	if connectorDoc.Prefix != prefix {
		t.Fatalf("connector prefix=%q want=%q", connectorDoc.Prefix, prefix)
	}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"api_key":"synthetic-key","version":0}`, http.StatusConflict},
		{`{"api_key":"synthetic-key","version":0,"connector_digest":"wrong"}`, http.StatusBadRequest},
		{`{"api_key":"synthetic-key","version":0,"connector_digest":null}`, http.StatusBadRequest},
	} {
		r := do(t, client, http.MethodPut, connectionBase+"/api-key", strings.NewReader(tc.body), headers)
		r.Body.Close()
		if r.StatusCode != tc.status {
			t.Fatalf("invalid bound registration status=%d want=%d", r.StatusCode, tc.status)
		}
	}
	anonymousConnector := do(t, newBrowserClient(t), http.MethodGet, connectionBase+"/api-key/connector", nil, nil)
	anonymousConnector.Body.Close()
	if anonymousConnector.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous connector status=%d", anonymousConnector.StatusCode)
	}
	boundBody, err := json.Marshal(map[string]any{"api_key": apiKeyValue, "version": 0, "connector_digest": connectorDoc.Digest})
	if err != nil {
		t.Fatal("encode API key binding")
	}
	bound := do(t, client, http.MethodPut, connectionBase+"/api-key", bytes.NewReader(boundBody), headers)
	bound.Body.Close()
	if bound.StatusCode != http.StatusOK {
		t.Fatalf("bound API key status=%d", bound.StatusCode)
	}
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupKeyBound)

	managedID := "use-grant-consumer-" + randomManagedUIID(t)
	managedBody := `{"id":"` + managedID + `","name":"Use grant consumer","confidential":false,"redirect_uris":["https://rp.example.test/use-grant"],"audience":["` + useGrantResource + `"],"scopes":["goauthy.connections.use"],"default_scopes":["goauthy.connections.use"],"enabled_flows":["authorization_code"]}`
	managed := do(t, client, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(managedBody), headers)
	var managedDoc struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if managed.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(managed.Body, 4096)).Decode(&managedDoc) != nil || managedDoc.ID != managedID || managedDoc.Revision <= 0 {
		managed.Body.Close()
		t.Fatalf("consumer create status=%d", managed.StatusCode)
	}
	managed.Body.Close()
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupConsumerCreated)
	expires := time.Now().Add(time.Hour).UnixMilli()
	grantBody := `{"consumer_client_id":"` + managedID + `","mode":"proxy","purpose":"sync","expires_at_unix_ms":` + strconv.FormatInt(expires, 10) + `}`
	for _, tc := range []struct {
		digest string
		status int
	}{
		{`null`, http.StatusBadRequest},
		{`"bad"`, http.StatusBadRequest},
		{`"` + strings.Repeat("A", 43) + `"`, http.StatusConflict},
	} {
		body := strings.TrimSuffix(grantBody, "}") + `,"connector_digest":` + tc.digest + `}`
		r := do(t, client, http.MethodPost, connectionBase+"/grants", strings.NewReader(body), headers)
		r.Body.Close()
		if r.StatusCode != tc.status {
			t.Fatalf("reviewed grant rejection=%d want=%d", r.StatusCode, tc.status)
		}
	}
	grant := do(t, client, http.MethodPost, connectionBase+"/grants", strings.NewReader(grantBody), headers)
	var grantDoc struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
		Revoked  bool   `json:"revoked"`
	}
	if grant.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(grant.Body, 16<<10)).Decode(&grantDoc) != nil || grantDoc.ID == "" || grantDoc.Revision != 1 || grantDoc.Revoked {
		grant.Body.Close()
		t.Fatalf("grant create status=%d", grant.StatusCode)
	}
	grant.Body.Close()
	isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupGrantCreated)
	var checkGrantStatus func(bool)
	if os.Getenv("GOAUTHY_E2E_GRANT_STATUS") == "1" {
		checkGrantStatus = grantStatusObserver(t, client, primary, headers, collectionID, connectionID, grantDoc.ID, managedID)
		checkGrantStatus(false)
	}
	var invokeToken string
	if os.Getenv("GOAUTHY_E2E_GRANT_INVOKE") == "1" {
		ensureResourcePermissionScope(t, client, primary, headers, "goauthy.connections.use")
		isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupScopeReady)
		invokeToken = issueGrantInvokeToken(t, client, primary, managedID, useGrantResource)
		isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupInvokeTokenIssued)
		if checkGrantStatus != nil {
			r := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/connections/"+collectionID+"/"+connectionID+"/grants/"+grantDoc.ID, nil, map[string]string{"Authorization": "Bearer " + invokeToken})
			r.Body.Close()
			if r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("use-only token read grant status=%d", r.StatusCode)
			}
		}
		assertGrantInvokeStatus(t, primary, grantDoc.ID, invokeToken, `{"operation":"unknown"}`, http.StatusBadRequest)
		assertGrantInvokeStatus(t, primary, "missing-grant", invokeToken, `{"operation":"account"}`, http.StatusNotFound)
		assertGrantInvokeStatus(t, primary, grantDoc.ID, "", `{"operation":"account"}`, http.StatusUnauthorized)
		wrongAudience := issueGrantInvokeToken(t, client, primary, managedID, "")
		assertGrantInvokeStatus(t, primary, grantDoc.ID, wrongAudience, `{"operation":"account"}`, http.StatusUnauthorized)
		if os.Getenv("GOAUTHY_E2E_ISOLATION113_FIXTURE_URL") != "" {
			isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupInvokeChecksPassed)
			isolation113SetupCheckpoint(t, isolation113Diagnostic, isolation113SetupDiagnosticEntered)
			runIsolation113Diagnostic(t, primary, secondary, user, password, grantDoc.ID, invokeToken)
		}
	}
	list := do(t, client, http.MethodGet, connectionBase+"/grants", nil, headers)
	var grants []map[string]any
	if list.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(list.Body, 32<<10)).Decode(&grants) != nil || len(grants) != 1 {
		list.Body.Close()
		t.Fatalf("grant list status=%d", list.StatusCode)
	}
	list.Body.Close()
	if strings.Contains(string(mustGrantList(t, client, connectionBase, headers)), "e2e-bound-api-key") {
		t.Fatal("grant list exposed raw API key")
	}
	rotateBody := `{"api_key":"e2e-rotated-key","version":1,"connector_digest":"` + connectorDoc.Digest + `"}`
	rotate := do(t, client, http.MethodPut, connectionBase+"/api-key", strings.NewReader(rotateBody), headers)
	rotate.Body.Close()
	if rotate.StatusCode != http.StatusOK {
		t.Fatalf("rotation status=%d", rotate.StatusCode)
	}
	stale := do(t, client, http.MethodPut, connectionBase+"/api-key", strings.NewReader(rotateBody), headers)
	stale.Body.Close()
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("stale rotation status=%d", stale.StatusCode)
	}
	revokePath := connectionBase + "/grants/" + url.PathEscape(grantDoc.ID)
	revoke := do(t, client, http.MethodDelete, revokePath, nil, sessionHeader(headers, "If-Match", `"1"`))
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("grant revoke status=%d", revoke.StatusCode)
	}
	if checkGrantStatus != nil {
		checkGrantStatus(true)
	}
	if invokeToken != "" {
		assertGrantInvokeStatus(t, primary, grantDoc.ID, invokeToken, `{"operation":"account"}`, http.StatusNotFound)
	}
	if os.Getenv("GOAUTHY_E2E_CREDENTIAL_DELIVERY") == "1" {
		t.Run("credential-delivery", func(t *testing.T) {
			testCredentialDeliveryLive(t, client, primary, cookie, headers, collectionID, connectionID, managedID, connectorDoc.Digest)
		})
	}
	replay := do(t, client, http.MethodDelete, revokePath, nil, sessionHeader(headers, "If-Match", `"1"`))
	replay.Body.Close()
	if replay.StatusCode != http.StatusConflict {
		t.Fatalf("grant revoke replay status=%d", replay.StatusCode)
	}
	revoked := mustGrantList(t, client, connectionBase, headers)
	if !strings.Contains(string(revoked), `"revoked":true`) {
		t.Fatalf("grant list missing revoked state: %s", revoked)
	}
	anonymous := do(t, newBrowserClient(t), http.MethodGet, connectionBase+"/grants", nil, nil)
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous grant list status=%d", anonymous.StatusCode)
	}
	if os.Getenv("GOAUTHY_E2E_GRANT_UI") == "1" {
		t.Run("service-access-browser", func(t *testing.T) {
			testConnectionGrantUI(t, client, primary, cookie, headers, collectionID, connectionID, managedID)
		})
	}
	if os.Getenv("GOAUTHY_E2E_HANDOFF") == "1" {
		t.Run("handoff-http", func(t *testing.T) {
			testUseHandoffLive(t, client, primary, cookie, headers, collectionID, connectionID, managedID)
		})
	}
	keyRevoke := do(t, client, http.MethodDelete, connectionBase+"/api-key", strings.NewReader(`{"version":2}`), headers)
	keyRevoke.Body.Close()
	if keyRevoke.StatusCode != http.StatusNoContent {
		t.Fatalf("key revoke status=%d", keyRevoke.StatusCode)
	}

	if os.Getenv("GOAUTHY_E2E_REGISTERED_KEY_UI") == "1" {
		t.Run("registered-key-browser", func(t *testing.T) {
			testConnectionAPIKeyUI(t, client, primary, cookie, headers, collectionID, collectionRevision, connectorDoc.Digest)
		})
	}
	connectionDelete := do(t, client, http.MethodDelete, connectionBase, nil, cloneCollectionHeaders(headers, connectionRevision))
	connectionDelete.Body.Close()
	if connectionDelete.StatusCode != http.StatusNoContent {
		t.Fatalf("connection cleanup status=%d", connectionDelete.StatusCode)
	}
	collectionDelete := do(t, client, http.MethodDelete, primary+"/auth/v1/auth-collections/"+collectionID, nil, cloneCollectionHeaders(headers, collectionRevision))
	collectionDelete.Body.Close()
	if collectionDelete.StatusCode != http.StatusNoContent {
		t.Fatalf("collection cleanup status=%d", collectionDelete.StatusCode)
	}
	managedDelete := do(t, client, http.MethodDelete, primary+"/auth/v1/clients/"+managedID, nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(managedDoc.Revision, 10))))
	managedDelete.Body.Close()
	if managedDelete.StatusCode != http.StatusNoContent {
		t.Fatalf("consumer cleanup status=%d", managedDelete.StatusCode)
	}
}

func isolation113FixtureOperations(connectorID, prefix, fixtureURL string) ([]saas.APIKeyOperationConfig, error) {
	u, err := url.Parse(fixtureURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() != "" || u.User != nil || u.Path != "/healthy" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("fixture URL must be portless HTTPS ending in /healthy")
	}
	apiBase := "https://" + u.Hostname()
	operations := []saas.APIKeyOperationConfig{
		{ID: "account", URL: apiBase + "/healthy", ResponseFields: map[string]string{"ok": "boolean"}},
		{ID: "slow-headers", URL: apiBase + "/slow-headers", ResponseFields: map[string]string{"ok": "boolean"}},
		{ID: "slow-body", URL: apiBase + "/slow-body", ResponseFields: map[string]string{"ok": "boolean"}},
		{ID: "failure", URL: apiBase + "/fail", ResponseFields: map[string]string{"ok": "boolean"}},
	}
	if _, err := saas.NewAPIKeyConnector(saas.APIKeyConnectorConfig{ID: connectorID, Header: "Authorization", Prefix: prefix, Operations: operations}); err != nil {
		return nil, err
	}
	return operations, nil
}

func isolation113SetupCheckpoint(t *testing.T, enabled bool, stage string) {
	t.Helper()
	if enabled {
		t.Logf("isolation113-setup-checkpoint stage=%s", stage)
	}
}

func runIsolation113Diagnostic(t *testing.T, primary, secondary, user, password, grant, token string) {
	t.Helper()
	invokeClient := isolation113InvokeClient(t)
	const phase = 16 * time.Second
	raw := os.Getenv("GOAUTHY_E2E_ISOLATION113_START_UNIX_MS")
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ms <= time.Now().Add(time.Second).UnixMilli() {
		t.Fatal("GOAUTHY_E2E_ISOLATION113_START_UNIX_MS must be a future Unix millisecond timestamp")
	}
	start := time.UnixMilli(ms)
	if wait := time.Until(start); wait > 0 {
		time.Sleep(wait)
	}
	var calls sync.WaitGroup
	phaseRun := func(name string, offset, duration time.Duration, routes []string) {
		begin := start.Add(offset)
		end := begin.Add(duration)
		for due := begin; due.Before(end); due = due.Add(3 * time.Second) {
			scheduledAt := due
			phaseName := name
			verifier := pkceVerifier(t)
			challenge := pkceChallenge(verifier)
			state := "isolation113-" + phaseName + "-" + strconv.FormatInt(scheduledAt.UnixNano(), 10)
			if wait := time.Until(due); wait > 0 {
				time.Sleep(wait)
			}
			requests := []func(){func() {
				t.Run(phaseName+"-iam-"+strconv.FormatInt(scheduledAt.UnixNano(), 10), func(t *testing.T) {
					requestStart := time.Now()
					outcome := "failed"
					trace := &isolation113StageTrace{}
					defer func() {
						t.Logf("isolation113 phase=%s route=iam outcome=%s scheduled_unix_ms=%d start_lag_ms=%.3f completion_latency_ms=%.3f", phaseName, outcome, scheduledAt.UnixMilli(), float64(requestStart.Sub(scheduledAt))/float64(time.Millisecond), float64(time.Since(requestStart))/float64(time.Millisecond))
						for _, leg := range trace.snapshot() {
							t.Logf("isolation113-stage phase=%s route=iam stage=%s outcome=%s status=%d elapsed_ms=%.3f scheduled_unix_ms=%d", phaseName, leg.Stage, leg.ErrorClass, leg.Status, leg.ElapsedMS, scheduledAt.UnixMilli())
						}
					}()
					_, _ = loginForCode(t, isolation113IAMClient(t, trace), primary, secondary, defaultRedirectURI, challenge, user, password, state)
					outcome = "success"
				})
			}}
			if len(routes) > 0 {
				operation := routes[int(scheduledAt.Sub(begin)/(3*time.Second))%len(routes)]
				requests = append(requests, func() {
					t.Run(phaseName+"-api-key-"+operation+"-"+strconv.FormatInt(scheduledAt.UnixNano(), 10), func(t *testing.T) {
						requestStart := time.Now()
						elapsed, status, err := invokeGrantMeasured(invokeClient, primary, grant, token, `{"operation":"`+operation+`"}`)
						outcome := "success"
						if err != nil {
							outcome = "transport-error"
						} else if status != http.StatusOK {
							outcome = "http-error"
						}
						t.Logf("isolation113 phase=%s route=api-key operation=%s outcome=%s status=%d start_lag_ms=%.3f completion_latency_ms=%.3f", phaseName, operation, outcome, status, float64(requestStart.Sub(scheduledAt))/float64(time.Millisecond), float64(elapsed)/float64(time.Millisecond))
						if failure := isolation113StatusFailure(operation, status, err); failure != "" {
							t.Errorf("scheduled API-key request %s", failure)
						}
					})
				})
			}
			launchIsolation113Tick(&calls, requests...)
		}
	}
	phaseRun("baseline", 0, phase, nil)
	phaseRun("mixed", phase, phase, []string{"slow-headers", "slow-body", "failure", "account"})
	phaseRun("recovery", 2*phase, 12*time.Second, []string{"account"})
	// Drain all scheduled IAM and provider requests before test cleanup.
	calls.Wait()
}

func isolation113StatusFailure(operation string, status int, requestErr error) string {
	if requestErr != nil {
		return "transport_error"
	}
	want := http.StatusBadGateway
	if operation == "account" {
		want = http.StatusOK
	}
	if status != want {
		return "unexpected_status"
	}
	return ""
}

func TestIsolation113ScheduledAPIKeyStatusExpectations(t *testing.T) {
	for _, tc := range []struct {
		operation string
		status    int
		want      string
	}{
		{"account", http.StatusOK, ""},
		{"account", http.StatusServiceUnavailable, "unexpected_status"},
		{"failure", http.StatusBadGateway, ""},
		{"slow-headers", http.StatusBadGateway, ""},
		{"slow-body", http.StatusServiceUnavailable, "unexpected_status"},
	} {
		if got := isolation113StatusFailure(tc.operation, tc.status, nil); got != tc.want {
			t.Errorf("operation=%s status=%d failure=%q want=%q", tc.operation, tc.status, got, tc.want)
		}
	}
	if got := isolation113StatusFailure("account", http.StatusOK, errors.New("private transport detail")); got != "transport_error" {
		t.Fatalf("transport failure classification=%q", got)
	}
}

func isolation113InvokeClient(t *testing.T) *http.Client {
	t.Helper()
	client := noRedirectClient(t, nil)
	client.Timeout = 25 * time.Second
	return client
}

func TestIsolation113InvokeClientDoesNotSendBrowserCookies(t *testing.T) {
	var invokeCookie string
	var gotBearer bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/owner" {
			http.SetCookie(w, &http.Cookie{Name: "owner-session", Value: "synthetic", Path: "/"})
			w.WriteHeader(http.StatusNoContent)
			return
		}
		invokeCookie = r.Header.Get("Cookie")
		gotBearer = r.Header.Get("Authorization") == "Bearer synthetic-token"
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := isolation113InvokeClient(t)
	if client.Timeout != 25*time.Second || client.Jar != nil {
		t.Fatalf("invoke client timeout=%s cookie_jar=%t", client.Timeout, client.Jar != nil)
	}
	ownerResponse, err := client.Get(server.URL + "/owner")
	if err != nil {
		t.Fatalf("owner setup request failed: %v", err)
	}
	ownerResponse.Body.Close()
	if ownerResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("owner setup status=%d", ownerResponse.StatusCode)
	}
	_, status, err := invokeGrantMeasured(client, server.URL, "grant", "synthetic-token", `{"operation":"account"}`)
	if err != nil || status != http.StatusOK || invokeCookie != "" || !gotBearer {
		t.Fatalf("invoke status=%d err=%v cookie_sent=%t bearer_sent=%t", status, err, invokeCookie != "", gotBearer)
	}
}

func TestSafeLogin403CategoryDoesNotExposeResponseBody(t *testing.T) {
	const privateMarker = "private-login-detail-should-not-escape"
	for _, tc := range []struct {
		body string
		want string
	}{
		{"Invalid login request\n", "invalid_login_request"},
		{privateMarker, "unclassified_403"},
	} {
		got := safeLogin403Category([]byte(tc.body))
		if got != tc.want || strings.Contains(got, privateMarker) {
			t.Fatalf("category=%q want=%q", got, tc.want)
		}
	}
}

func launchIsolation113Tick(calls *sync.WaitGroup, requests ...func()) {
	for _, request := range requests {
		calls.Add(1)
		go func(request func()) {
			defer calls.Done()
			request()
		}(request)
	}
}

func invokeGrantMeasured(client *http.Client, base, grant, token, body string) (time.Duration, int, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/auth/v1/connection-grants/"+url.PathEscape(grant)+"/invoke", strings.NewReader(body))
	if err != nil {
		return time.Since(start), 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	r, err := client.Do(req)
	if err != nil {
		return time.Since(start), 0, err
	}
	defer r.Body.Close()
	_, readErr := io.Copy(io.Discard, io.LimitReader(r.Body, 16<<10))
	return time.Since(start), r.StatusCode, readErr
}

// isolation113StageTrace records per-HTTP-leg timing for the IAM login flow. It
// keeps a fixed stage/outcome enum and numeric latency/status only: never a URL,
// query string, header, token, credential, or response body.
type isolation113StageTrace struct {
	mu   sync.Mutex
	legs []isolation113StageLeg
}

type isolation113StageLeg struct {
	Stage      string
	ElapsedMS  float64
	Status     int
	ErrorClass string
}

func (t *isolation113StageTrace) record(stage string, elapsed time.Duration, status int, err error) {
	class := "none"
	var networkError net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		class = "timeout"
	case errors.As(err, &networkError) && networkError.Timeout():
		class = "timeout"
	case errors.Is(err, context.Canceled):
		class = "canceled"
	case err != nil:
		class = "transport"
	}
	t.mu.Lock()
	t.legs = append(t.legs, isolation113StageLeg{Stage: stage, ElapsedMS: float64(elapsed) / float64(time.Millisecond), Status: status, ErrorClass: class})
	t.mu.Unlock()
}

func (t *isolation113StageTrace) snapshot() []isolation113StageLeg {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]isolation113StageLeg(nil), t.legs...)
}

// isolation113StageTransport classifies each IAM leg by a fixed method+path
// enum and records time-to-response-headers only; the response body is read by
// the caller after RoundTrip returns, so body time is not included. It never
// inspects or retains request contents.
type isolation113StageTransport struct {
	base  http.RoundTripper
	trace *isolation113StageTrace
}

func (t *isolation113StageTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	stage := "other"
	switch {
	case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/oidc/authorize"):
		stage = "authorize-get"
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/auth/login"):
		stage = "login-post"
	}
	start := time.Now()
	response, err := t.base.RoundTrip(req)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	t.trace.record(stage, time.Since(start), status, err)
	return response, err
}

func isolation113IAMClient(t *testing.T, trace *isolation113StageTrace) *http.Client {
	t.Helper()
	client := newBrowserClient(t)
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = &isolation113StageTransport{base: base, trace: trace}
	return client
}

func mustGrantList(t *testing.T, client *http.Client, base string, headers map[string]string) []byte {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/grants", nil, headers)
	b, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
	r.Body.Close()
	if r.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("grant list status=%d err=%v", r.StatusCode, err)
	}
	return b
}

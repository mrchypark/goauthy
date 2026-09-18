package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func testCredentialDeliveryLive(t *testing.T, owner *http.Client, base string, cookie *http.Cookie, headers map[string]string, collection, connection, consumer, connectorDigest string) {
	t.Helper()
	if os.Getenv("GOAUTHY_E2E_CREDENTIAL_DELIVERY") != "1" {
		return
	}
	clientID := "credential-delivery-" + randomManagedUIID(t)
	clientBody := `{"id":"` + clientID + `","name":"Credential delivery E2E","confidential":true,"redirect_uris":["https://rp.example.test/use-grant"],"audience":["` + useGrantResource + `"],"scopes":["goauthy.connections.use","goauthy.connections.write","goauthy.connections.read"],"default_scopes":["goauthy.connections.use","goauthy.connections.write","goauthy.connections.read"],"enabled_flows":["authorization_code"]}`
	r := do(t, owner, http.MethodPost, base+"/auth/v1/clients", strings.NewReader(clientBody), headers)
	r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("credential consumer create status=%d", r.StatusCode)
	}
	t.Cleanup(func() {
		get := do(t, owner, http.MethodGet, base+"/auth/v1/clients/"+url.PathEscape(clientID), nil, headers)
		var current struct {
			Revision int64 `json:"revision"`
		}
		err := json.NewDecoder(io.LimitReader(get.Body, 4096)).Decode(&current)
		get.Body.Close()
		if get.StatusCode != http.StatusOK || err != nil || current.Revision < 1 {
			t.Error("credential consumer cleanup lookup failed")
		} else {
			remove := do(t, owner, http.MethodDelete, base+"/auth/v1/clients/"+url.PathEscape(clientID), nil, sessionHeader(headers, "If-Match", `"`+strconv.FormatInt(current.Revision, 10)+`"`))
			remove.Body.Close()
			if remove.StatusCode != http.StatusNoContent {
				t.Errorf("credential consumer cleanup status=%d", remove.StatusCode)
			}
		}
	})
	secretResponse := do(t, owner, http.MethodPost, base+"/auth/v1/clients/"+url.PathEscape(clientID)+"/secret", nil, headers)
	var secretDoc struct {
		Secret string `json:"secret"`
	}
	err := json.NewDecoder(io.LimitReader(secretResponse.Body, 4096)).Decode(&secretDoc)
	secretResponse.Body.Close()
	if secretResponse.StatusCode != http.StatusOK || err != nil || secretDoc.Secret == "" {
		t.Fatal("credential consumer secret was not issued")
	}

	token := issueGrantResourceTokenWithSecret(t, owner, base, clientID, useGrantResource, "goauthy.connections.use", secretDoc.Secret)
	connectionURL := base + "/auth/v1/account/connections/" + url.PathEscape(collection) + "/" + url.PathEscape(connection)
	grantBody := `{"consumer_client_id":"` + clientID + `","mode":"credential_delivery","purpose":"credential delivery acceptance","expires_at_unix_ms":` + formatUnixMillis(time.Now().Add(time.Hour)) + `,"connector_digest":"` + connectorDigest + `"}`
	grantID := ""
	grantDoc := struct {
		ID         string `json:"id"`
		Consumer   string `json:"consumer_client_id"`
		Mode       string `json:"mode"`
		Digest     string `json:"connector_digest"`
		Provider   string `json:"provider_id"`
		Generation string `json:"generation"`
		Expires    int64  `json:"expires_at_unix_ms"`
	}{}
	if os.Getenv("GOAUTHY_E2E_DELIVERY_HANDOFF_UI") == "1" {
		writeToken := issueGrantResourceTokenWithSecret(t, owner, base, clientID, useGrantResource, "goauthy.connections.write", secretDoc.Secret)
		grantID = credentialDeliveryHandoffGrant(t, owner, base, headers, cookie, collection, connection, clientID, connectorDigest, writeToken)
	} else {
		grant := do(t, owner, http.MethodPost, connectionURL+"/grants", strings.NewReader(grantBody), headers)
		err = json.NewDecoder(io.LimitReader(grant.Body, 4096)).Decode(&grantDoc)
		grant.Body.Close()
		if grant.StatusCode != http.StatusCreated || err != nil || grantDoc.ID == "" {
			t.Fatalf("credential delivery grant status=%d", grant.StatusCode)
		}
		grantID = grantDoc.ID
	}
	readToken := issueGrantResourceTokenWithSecret(t, owner, base, clientID, useGrantResource, "goauthy.connections.read", secretDoc.Secret)
	detail := do(t, newBrowserClient(t), http.MethodGet, base+"/auth/v1/connections/"+url.PathEscape(collection)+"/"+url.PathEscape(connection)+"/grants/"+url.PathEscape(grantID), nil, map[string]string{"Authorization": "Bearer " + readToken})
	var status struct {
		Grant      json.RawMessage `json:"grant"`
		Generation string          `json:"connection_generation"`
	}
	err = json.NewDecoder(io.LimitReader(detail.Body, 8192)).Decode(&status)
	detail.Body.Close()
	if detail.StatusCode != http.StatusOK || err != nil || json.Unmarshal(status.Grant, &grantDoc) != nil || grantDoc.ID != grantID || grantDoc.Consumer != clientID || grantDoc.Mode != "credential_delivery" || grantDoc.Digest != connectorDigest || grantDoc.Provider == "" || grantDoc.Generation == "" || status.Generation != grantDoc.Generation || grantDoc.Expires <= 0 {
		t.Fatalf("credential delivery grant metadata status=%d", detail.StatusCode)
	}

	bearer := map[string]string{"Authorization": "Bearer " + token}
	deliver := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-grants/"+url.PathEscape(grantID)+"/credential", nil, bearer)
	var delivered struct {
		Kind       string `json:"kind"`
		APIKey     string `json:"api_key"`
		Version    int64  `json:"credential_version"`
		GrantID    string `json:"grant_id"`
		Digest     string `json:"connector_digest"`
		Provider   string `json:"provider_id"`
		Generation string `json:"connection_generation"`
		Expires    int64  `json:"consent_expires_at_unix_ms"`
		Header     string `json:"header"`
		Prefix     string `json:"prefix"`
	}
	deliverBody, readErr := io.ReadAll(io.LimitReader(deliver.Body, 16<<10))
	err = json.Unmarshal(deliverBody, &delivered)
	deliver.Body.Close()
	var fields map[string]json.RawMessage
	fieldErr := json.Unmarshal(deliverBody, &fields)
	if deliver.StatusCode != http.StatusOK || readErr != nil || err != nil || fieldErr != nil || delivered.Kind != "api_key" || delivered.APIKey != "e2e-rotated-key" || delivered.Version != 2 || delivered.GrantID != grantID || delivered.Digest != connectorDigest || deliver.Header.Get("Cache-Control") != "no-store" || fields["refresh_token"] != nil || fields["client_secret"] != nil || fields["access_token"] != nil {
		t.Fatal("credential delivery response did not validate")
	}
	wantPrefix := "Bearer "
	if os.Getenv("GOAUTHY_E2E_RAW_AUTHORIZATION") == "1" {
		wantPrefix = ""
	}
	if len(fields) != 10 || delivered.Provider != grantDoc.Provider || delivered.Generation != grantDoc.Generation || delivered.Expires != grantDoc.Expires || delivered.Header == "" || delivered.Prefix != wantPrefix {
		t.Fatal("credential delivery binding metadata did not validate")
	}
	conductor := os.Getenv("GOAUTHY_E2E_CONDUCTOR_DELIVERY_PROJECT_DIR")
	runConductor := func(denied bool) {
		if conductor == "" {
			return
		}
		if !filepath.IsAbs(conductor) || delivered.Prefix != "" || delivered.Header != "Authorization" {
			t.Fatal("invalid Conductor fixture configuration")
		}
		binding, err := json.Marshal(map[string]any{"grant_id": grantID, "provider_id": delivered.Provider, "connection_generation": delivered.Generation, "credential_version": delivered.Version, "connector_digest": delivered.Digest, "header": delivered.Header, "prefix": delivered.Prefix, "url": "https://openapi.gowid.com/v2/expense-statements", "consent_expires_at_unix_ms": delivered.Expires})
		if err != nil {
			t.Fatal("encode Conductor fixture binding")
		}
		cmd := exec.CommandContext(t.Context(), "go", "test", "-mod=readonly", "-count=1", "./internal/connectors", "-run", "^TestAPIKeyDeliveryGoAuthyFixture$")
		cmd.Dir = conductor
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "CONDUCTOR_DELIVERY_") {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		deny := "0"
		if denied {
			deny = "1"
		}
		cmd.Env = append(cmd.Env, "CONDUCTOR_DELIVERY_LIVE=1", "CONDUCTOR_DELIVERY_ISSUER="+base, "CONDUCTOR_DELIVERY_CA_FILE="+os.Getenv("SSL_CERT_FILE"), "CONDUCTOR_DELIVERY_HUMAN_TOKEN="+token, "CONDUCTOR_DELIVERY_BINDING="+string(binding), "CONDUCTOR_DELIVERY_EXPECTED_API_KEY=e2e-rotated-key", "CONDUCTOR_DELIVERY_EXPECT_DENIED="+deny)
		// Never echo child output: it executes a consumer repository with a
		// disposable human credential. Secrets stay out of parent test logs.
		if err := cmd.Run(); err != nil {
			t.Fatalf("Conductor delivery bridge failed (denied=%t): %v", denied, err)
		}
		t.Logf("Conductor delivery bridge passed (denied=%t)", denied)
	}
	runConductor(false)
	if os.Getenv("GOAUTHY_E2E_BEESUH_DELIVERY_PROJECT_DIR") != "" {
		if delivered.Header != "Authorization" || delivered.Prefix != "Bearer " {
			t.Fatal("Beesuh delivery fixture requires reviewed Bearer key injection")
		}
		testBeesuhDeliveryBridge(t, owner, base, headers, collection, connection, clientID, token, grantID, delivered.Provider, delivered.Digest, delivered.Generation, delivered.Expires)
	}
	proxyBody := `{"consumer_client_id":"` + clientID + `","mode":"proxy","purpose":"proxy denial","expires_at_unix_ms":` + formatUnixMillis(time.Now().Add(time.Hour)) + `,"connector_digest":"` + connectorDigest + `"}`
	proxy := do(t, owner, http.MethodPost, connectionURL+"/grants", strings.NewReader(proxyBody), headers)
	var proxyDoc struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(io.LimitReader(proxy.Body, 4096)).Decode(&proxyDoc)
	proxy.Body.Close()
	if proxy.StatusCode != http.StatusCreated || proxyDoc.ID == "" {
		t.Fatalf("proxy grant create status=%d", proxy.StatusCode)
	}
	proxyAttempt := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-grants/"+url.PathEscape(proxyDoc.ID)+"/credential", nil, bearer)
	proxyAttempt.Body.Close()
	if proxyAttempt.StatusCode != http.StatusNotFound {
		t.Fatalf("proxy credential delivery status=%d", proxyAttempt.StatusCode)
	}
	proxyRevoke := do(t, owner, http.MethodDelete, connectionURL+"/grants/"+url.PathEscape(proxyDoc.ID), nil, sessionHeader(headers, "If-Match", `"1"`))
	proxyRevoke.Body.Close()
	if proxyRevoke.StatusCode != http.StatusNoContent {
		t.Fatalf("proxy grant revoke status=%d", proxyRevoke.StatusCode)
	}
	publicToken := issueGrantResourceToken(t, owner, base, consumer, useGrantResource, "goauthy.connections.use")
	publicAttempt := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/credential", nil, map[string]string{"Authorization": "Bearer " + publicToken})
	publicAttempt.Body.Close()
	if publicAttempt.StatusCode != http.StatusNotFound {
		t.Fatalf("public consumer credential delivery status=%d", publicAttempt.StatusCode)
	}

	revoke := do(t, owner, http.MethodDelete, connectionURL+"/grants/"+url.PathEscape(grantDoc.ID), nil, sessionHeader(headers, "If-Match", `"1"`))
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("credential delivery grant revoke status=%d", revoke.StatusCode)
	}
	after := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/credential", nil, bearer)
	after.Body.Close()
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked credential delivery status=%d", after.StatusCode)
	}
	runConductor(true)
}

func formatUnixMillis(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }

func credentialDeliveryHandoffGrant(t *testing.T, owner *http.Client, base string, headers map[string]string, cookie *http.Cookie, collection, connection, consumer, digest, writeToken string) string {
	t.Helper()
	if cookie == nil {
		t.Fatal("owner browser session cookie missing")
	}
	state := strings.Repeat("H", 32)
	body := `{"collection_id":"` + collection + `","connection_id":"` + connection + `","consumer_client_id":"` + consumer + `","mode":"credential_delivery","purpose":"credential delivery handoff","expires_at_unix_ms":` + formatUnixMillis(time.Now().Add(time.Hour)) + `,"return_uri":"https://rp.example.test/use-grant","state":"` + state + `"}`
	r := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-handoffs", strings.NewReader(body), map[string]string{"Authorization": "Bearer " + writeToken, "Content-Type": "application/json"})
	var start struct {
		ReviewURI string `json:"review_uri"`
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&start)
	r.Body.Close()
	if r.StatusCode != http.StatusCreated || err != nil || start.ReviewURI == "" {
		t.Fatalf("credential handoff create status=%d", r.StatusCode)
	}
	connectionURL := base + "/auth/v1/account/connections/" + url.PathEscape(collection) + "/" + url.PathEscape(connection)
	before := lenGrantList(t, mustGrantList(t, owner, connectionURL, headers))
	ctx, cancel := newCollectionUIContext(t, cookie, base)
	defer cancel()
	if err := chromedp.Run(ctx, chromedp.Navigate(start.ReviewURI), chromedp.WaitVisible("#handoff-approve")); err != nil {
		t.Fatalf("open credential handoff: %v", err)
	}
	var pageText string
	if err := chromedp.Run(ctx, chromedp.TextContent("#main-content", &pageText)); err != nil || !strings.Contains(pageText, "The service will receive your original API key") || !strings.Contains(pageText, "cannot recall a key already delivered") || strings.Contains(pageText, "not your API key") || strings.Contains(pageText, "e2e-rotated-key") || !strings.Contains(pageText, digest) {
		t.Fatal("credential handoff page omitted raw-key warning")
	}
	var valid bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('#handoff-approve')?.checkValidity() === true`, &valid)); err != nil || valid {
		t.Fatal("credential handoff approval was valid before review")
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#handoff-approve button[type="submit"]`), chromedp.WaitVisible("#handoff-approve")); err != nil {
		t.Fatalf("unchecked credential handoff approval: %v", err)
	}
	if got := lenGrantList(t, mustGrantList(t, owner, connectionURL, headers)); got != before {
		t.Fatal("unchecked credential handoff created a grant")
	}
	if screenshot := os.Getenv("GOAUTHY_E2E_HANDOFF_SCREENSHOT"); screenshot != "" {
		var image []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&image, 90)); err != nil {
			t.Fatalf("capture credential handoff screenshot: %v", err)
		}
		if err := os.WriteFile(screenshot, image, 0600); err != nil {
			t.Fatalf("write credential handoff screenshot: %v", err)
		}
	}
	if err := chromedp.Run(ctx, chromedp.Click(`#handoff-approve input[name="reviewed"]`)); err != nil {
		t.Fatal(err)
	}
	response, err := chromedp.RunResponse(ctx, chromedp.Click(`#handoff-approve button[type="submit"]`))
	if err != nil || response == nil || response.Status != http.StatusOK {
		t.Fatalf("approve credential handoff: %v", err)
	}
	var href string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('#handoff-return')?.href || ''`, &href)); err != nil {
		t.Fatal("read credential handoff return")
	}
	u, err := url.Parse(href)
	if err != nil || u.Query().Get("state") != state || u.Query().Get("grant_id") == "" || u.Query().Get("error") != "" {
		t.Fatal("credential handoff return is invalid")
	}
	assertHandoffReturn(t, href, state, true)
	if got := lenGrantList(t, mustGrantList(t, owner, connectionURL, headers)); got != before+1 {
		t.Fatal("credential handoff did not create exactly one grant")
	}
	return u.Query().Get("grant_id")
}

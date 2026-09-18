package browser

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestConnectionOAuth2RegisteredSuccess(t *testing.T) {
	providerBase := strings.TrimRight(os.Getenv("GOAUTHY_E2E_OAUTH2_PROVIDER_URL"), "/")
	providerID := os.Getenv("GOAUTHY_E2E_OAUTH2_PROVIDER_ID")
	clientID, clientSecret := os.Getenv("GOAUTHY_E2E_OAUTH2_CLIENT_ID"), os.Getenv("GOAUTHY_E2E_OAUTH2_CLIENT_SECRET")
	if providerBase == "" || providerID == "" || clientID == "" || clientSecret == "" {
		if os.Getenv("GOAUTHY_E2E_REGISTERED_OAUTH2") == "1" {
			t.Fatal("GOAUTHY_E2E_REGISTERED_OAUTH2=1 requires GOAUTHY_E2E_OAUTH2_PROVIDER_URL, GOAUTHY_E2E_OAUTH2_PROVIDER_ID, GOAUTHY_E2E_OAUTH2_CLIENT_ID, and GOAUTHY_E2E_OAUTH2_CLIENT_SECRET")
		}
		t.Skip("set GOAUTHY_E2E_OAUTH2_PROVIDER_URL, GOAUTHY_E2E_OAUTH2_PROVIDER_ID, GOAUTHY_E2E_OAUTH2_CLIENT_ID, and GOAUTHY_E2E_OAUTH2_CLIENT_SECRET to run registered OAuth2 E2E")
	}
	providerURL, err := url.Parse(providerBase)
	if err != nil || providerURL.Scheme != "https" || providerURL.Hostname() == "" || providerURL.User != nil || providerURL.RawQuery != "" || providerURL.Fragment != "" {
		t.Fatal("GOAUTHY_E2E_OAUTH2_PROVIDER_URL must be an exact HTTPS fixture base")
	}
	primary, secondary, user, password, _ := browserE2EConfig(t)
	owner := newBrowserClient(t)
	_, cookie := loginForCode(t, owner, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "registered-oauth2-success")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf, "Sec-Fetch-Site": "same-origin"}
	providerCallback := primary + "/auth/v1/saas/callback/" + url.PathEscape(providerID)
	providerBody := `{"id":"` + providerID + `","name":"Registered OAuth2 success","kind":"oauth2","enabled":true,"client_id":"` + clientID + `","client_secret":"` + clientSecret + `","callback_uri":"` + providerCallback + `","auth_endpoint":"` + providerBase + `/authorize","token_endpoint":"` + providerBase + `/token","scopes":["account"],"auth_style":"header","identity_endpoint":"` + providerBase + `/userinfo","subject_field":"sub"}`
	providerResponse := do(t, owner, http.MethodPost, primary+"/auth/v1/saas/providers", strings.NewReader(providerBody), headers)
	if providerResponse.StatusCode != http.StatusCreated {
		providerResponse.Body.Close()
		t.Fatalf("provider create status=%d", providerResponse.StatusCode)
	}
	providerRevision := providerResponse.Header.Get("ETag")
	providerResponse.Body.Close()
	if providerRevision == "" {
		t.Fatal("provider create missing ETag")
	}
	providerDeleted := false
	t.Cleanup(func() {
		if providerDeleted {
			return
		}
		r := do(t, owner, http.MethodDelete, primary+"/auth/v1/saas/providers/"+url.PathEscape(providerID), nil, sessionHeader(headers, "If-Match", providerRevision))
		r.Body.Close()
	})

	collectionID := uniqueCollectionID(t)
	collectionResponse := do(t, owner, http.MethodPost, primary+"/auth/v1/auth-collections", strings.NewReader(`{"id":"`+collectionID+`","name":"Registered OAuth2 success","auth_method":"oauth2","enabled":true,"fields":[],"provider_ids":["`+providerID+`"]}`), headers)
	_, collectionRevision := readCollection(t, collectionResponse, http.StatusCreated)
	collectionDeleted := false
	t.Cleanup(func() {
		if collectionDeleted {
			return
		}
		r := do(t, owner, http.MethodDelete, primary+"/auth/v1/auth-collections/"+url.PathEscape(collectionID), nil, cloneCollectionHeaders(headers, collectionRevision))
		r.Body.Close()
	})

	connectionResponse := do(t, owner, http.MethodPost, primary+"/auth/v1/account/connections/"+url.PathEscape(collectionID), strings.NewReader(`{"definition_revision":1,"metadata":{}}`), headers)
	connection, connectionRevision := readCollection(t, connectionResponse, http.StatusCreated)
	connectionID, ok := connection["id"].(string)
	if !ok || connectionID == "" {
		t.Fatal("connection ID missing")
	}
	connectionDeleted := false
	t.Cleanup(func() {
		if connectionDeleted {
			return
		}
		r := do(t, owner, http.MethodDelete, primary+"/auth/v1/account/connections/"+url.PathEscape(collectionID)+"/"+url.PathEscape(connectionID), nil, cloneCollectionHeaders(headers, connectionRevision))
		r.Body.Close()
	})

	statusURL := primary + "/auth/v1/account/connections/" + url.PathEscape(collectionID) + "/" + url.PathEscape(connectionID) + "/oauth2"
	assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), false, "draft", 0, nil, false)
	var startBody struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	connectionUI := os.Getenv("GOAUTHY_E2E_OAUTH2_CONNECTION_UI") == "1"
	reconnectUI := os.Getenv("GOAUTHY_E2E_OAUTH2_RECONNECT_UI") == "1"
	if reconnectUI && (!connectionUI || os.Getenv("GOAUTHY_E2E_OAUTH2_CALLBACK_UI") != "1" || os.Getenv("GOAUTHY_E2E_OAUTH2_GRANT_UI") != "1") {
		t.Fatal("reconnect UI requires connection, callback and grant UI profiles")
	}
	if connectionUI {
		startBody.AuthorizationURL = oauth2ConnectionUIAction(t, cookie, primary, collectionID, connectionID, providerID, "start", "", 0)
	} else {
		start := do(t, owner, http.MethodPost, statusURL, strings.NewReader(`{"provider_id":"`+providerID+`"}`), headers)
		if start.StatusCode != http.StatusOK || json.NewDecoder(start.Body).Decode(&startBody) != nil {
			start.Body.Close()
			t.Fatalf("oauth2 start status=%d", start.StatusCode)
		}
		start.Body.Close()
	}
	authorizationURL, err := url.Parse(startBody.AuthorizationURL)
	if err != nil || authorizationURL.Query().Get("redirect_uri") != providerCallback || authorizationURL.Query().Get("scope") != "account" || authorizationURL.Query().Get("state") == "" {
		t.Fatal("authorization URL does not match the registered callback/scope/state")
	}
	if authorizationURL.Scheme != providerURL.Scheme || authorizationURL.Host != providerURL.Host || authorizationURL.Path != "/authorize" {
		t.Fatal("authorization URL escaped the fixture origin")
	}

	providerClient := oauth2FixtureClient(t, providerURL)
	beforeStats := readOAuth2FixtureStats(t, providerClient, providerBase)
	if os.Getenv("GOAUTHY_E2E_OAUTH2_CALLBACK_UI") == "1" {
		completeOAuth2Browser(t, cookie, primary, startBody.AuthorizationURL, providerCallback)
	} else {
		authorize := do(t, providerClient, http.MethodGet, startBody.AuthorizationURL, nil, nil)
		if authorize.StatusCode != http.StatusFound && authorize.StatusCode != http.StatusSeeOther {
			authorize.Body.Close()
			t.Fatalf("provider authorize status=%d", authorize.StatusCode)
		}
		providerLocation := authorize.Header.Get("Location")
		authorize.Body.Close()
		callback, err := url.Parse(providerLocation)
		if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != providerCallback || callback.Query().Get("state") != authorizationURL.Query().Get("state") || callback.Query().Get("code") == "" {
			t.Fatal("provider callback location does not match the registered callback/state/code")
		}
		completed := do(t, owner, http.MethodGet, callback.String(), nil, headers)
		assertRegisteredOAuth2Completion(t, completed)
	}
	assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), true, "ready", 1, []string{"account"}, true)
	checkDelivery, consumerRefresh, revokeDelivery, deniedDelivery := oauth2DeliveryProbe(t, owner, primary, cookie, headers, collectionID, connectionID, providerID, providerBase)
	checkDelivery(1)
	restartChecks := 0
	if os.Getenv("GOAUTHY_E2E_OAUTH2_ACTIVE_RESTART") == "1" {
		awaitOAuth2Restart(t, 1)
		assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), true, "ready", 1, []string{"account"}, true)
		checkDelivery(1)
		restartChecks++
	}

	if os.Getenv("GOAUTHY_E2E_CONSUMER_REFRESH") == "1" {
		consumerRefresh(1)
		assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), true, "ready", 2, []string{"account"}, true)
	} else if connectionUI {
		oauth2ConnectionUIAction(t, cookie, primary, collectionID, connectionID, providerID, "refresh", "ready", 2)
		assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), true, "ready", 2, []string{"account"}, true)
	} else {
		refreshed := do(t, owner, http.MethodPost, statusURL+"/refresh", strings.NewReader(`{"version":1}`), headers)
		assertRegisteredOAuth2Status(t, refreshed, true, "ready", 2, []string{"account"}, true)
	}
	checkDelivery(2)
	if os.Getenv("GOAUTHY_E2E_OAUTH2_ACTIVE_RESTART") == "1" {
		awaitOAuth2Restart(t, 2)
		assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), true, "ready", 2, []string{"account"}, true)
		checkDelivery(2)
		restartChecks++
	}
	stale := do(t, owner, http.MethodPost, statusURL+"/refresh", strings.NewReader(`{"version":1}`), headers)
	assertMetadataOnlyOAuth2Response(t, stale, http.StatusNotFound)
	if !reconnectUI {
		revokeDelivery()
	}

	if connectionUI {
		oauth2ConnectionUIAction(t, cookie, primary, collectionID, connectionID, providerID, "revoke", "revoked", 2)
	} else {
		revoke := do(t, owner, http.MethodDelete, statusURL, strings.NewReader(`{"version":2}`), headers)
		revoke.Body.Close()
		if revoke.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke status=%d", revoke.StatusCode)
		}
	}
	assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), false, "revoked", 2, []string{"account"}, true)
	wantAuthorize, wantToken, wantUserInfo := 1, 2, 4+restartChecks
	if reconnectUI {
		// Keep the original grant unrevoked: a generation change, not explicit
		// consent deletion, must prevent it from authorizing the new connection.
		deniedDelivery()
		oauth2ConnectionUIAction(t, cookie, primary, collectionID, connectionID, providerID, "reconnect", "reconnecting", 2)
		assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), false, "reconnecting", 2, nil, false)
		connectionURL := strings.TrimSuffix(statusURL, "/oauth2")
		current, revision := readCollection(t, do(t, owner, http.MethodGet, connectionURL, nil, headers), http.StatusOK)
		connectionRevision = revision // Reconnect changes the row revision used by cleanup.
		if current["id"] != connectionID || current["revision"] == connection["revision"] || current["definition_revision"] != connection["definition_revision"] {
			t.Fatal("reconnect failed to preserve the connection or advance its revision")
		}
		deniedDelivery()
		reconnectURL := oauth2ConnectionUIAction(t, cookie, primary, collectionID, connectionID, providerID, "start", "", 0)
		completeOAuth2Browser(t, cookie, primary, reconnectURL, providerCallback)
		assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), true, "ready", 3, []string{"account"}, true)
		deniedDelivery()
		staleRevoke := do(t, owner, http.MethodDelete, statusURL, strings.NewReader(`{"version":2}`), headers)
		assertMetadataOnlyOAuth2Response(t, staleRevoke, http.StatusConflict)
		revokeDelivery()
		newDelivery, _, revokeNewDelivery, _ := oauth2DeliveryProbe(t, owner, primary, cookie, headers, collectionID, connectionID, providerID, providerBase)
		newDelivery(3)
		var generations []struct {
			Generation string `json:"generation"`
		}
		if err := json.Unmarshal(mustGrantList(t, owner, connectionURL, headers), &generations); err != nil || len(generations) != 2 || generations[0].Generation == "" || generations[1].Generation == "" || generations[0].Generation == generations[1].Generation {
			t.Fatal("new consent did not bind a distinct connection generation")
		}
		deniedDelivery()
		revokeNewDelivery()
		oauth2ConnectionUIAction(t, cookie, primary, collectionID, connectionID, providerID, "revoke", "revoked", 3)
		assertRegisteredOAuth2Status(t, do(t, owner, http.MethodGet, statusURL, nil, headers), false, "revoked", 3, []string{"account"}, true)
		wantAuthorize++
		wantToken++
		wantUserInfo += 2 // Reconnect identity lookup and explicit new-consent receipt.
	}
	afterStats := readOAuth2FixtureStats(t, providerClient, providerBase)
	if afterStats.Authorize-beforeStats.Authorize != wantAuthorize || afterStats.Token-beforeStats.Token != wantToken || afterStats.UserInfo-beforeStats.UserInfo != wantUserInfo {
		t.Fatalf("provider stats delta=%+v, want authorize=%d token=%d userinfo=%d", oauth2FixtureStatsSnapshot{afterStats.Authorize - beforeStats.Authorize, afterStats.Token - beforeStats.Token, afterStats.UserInfo - beforeStats.UserInfo}, wantAuthorize, wantToken, wantUserInfo)
	}

	r := do(t, owner, http.MethodDelete, primary+"/auth/v1/account/connections/"+url.PathEscape(collectionID)+"/"+url.PathEscape(connectionID), nil, cloneCollectionHeaders(headers, connectionRevision))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("connection cleanup status=%d", r.StatusCode)
	}
	connectionDeleted = true
	r = do(t, owner, http.MethodDelete, primary+"/auth/v1/auth-collections/"+url.PathEscape(collectionID), nil, cloneCollectionHeaders(headers, collectionRevision))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("collection cleanup status=%d", r.StatusCode)
	}
	collectionDeleted = true
	r = do(t, owner, http.MethodDelete, primary+"/auth/v1/saas/providers/"+url.PathEscape(providerID), nil, sessionHeader(headers, "If-Match", providerRevision))
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("provider cleanup status=%d", r.StatusCode)
	}
	providerDeleted = true
}

// The shell restarts only GoAuthy, leaving this process and the provider alive.
// Marker files contain no session cookies, access tokens or client secrets.
func awaitOAuth2Restart(t *testing.T, phase int) {
	t.Helper()
	dir := os.Getenv("GOAUTHY_E2E_OAUTH2_RESTART_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("active OAuth restart requires an absolute handshake directory")
	}
	ready := filepath.Join(dir, "ready-"+strconv.Itoa(phase))
	if _, err := os.Stat(ready); !os.IsNotExist(err) {
		t.Fatal("OAuth restart acknowledgement already exists or cannot be checked")
	}
	f, err := os.OpenFile(filepath.Join(dir, "request-"+strconv.Itoa(phase)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create OAuth restart request: ", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(90 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-t.Context().Done():
			t.Fatal("OAuth restart test canceled")
		case <-timeout.C:
			t.Fatal("OAuth restart acknowledgement timed out")
		case <-ticker.C:
			if info, err := os.Stat(ready); err == nil {
				if !info.Mode().IsRegular() || info.Size() != 0 {
					t.Fatal("invalid OAuth restart acknowledgement")
				}
				return
			} else if !os.IsNotExist(err) {
				t.Fatal("read OAuth restart acknowledgement: ", err)
			}
		}
	}
}

func oauth2FixtureClient(t *testing.T, fixture *url.URL) *http.Client {
	t.Helper()
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile := os.Getenv("SSL_CERT_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			t.Fatalf("read fixture CA: %v", err)
		}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: fixture.Hostname()}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func assertRegisteredOAuth2Status(t *testing.T, response *http.Response, connected bool, state string, version int64, scopes []string, account bool) {
	t.Helper()
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("OAuth2 metadata status=%d err=%v body=%s", response.StatusCode, err, data)
	}
	assertMetadataOnlyOAuth2Body(t, data)
	var got struct {
		Connected bool     `json:"connected"`
		State     string   `json:"state"`
		Version   int64    `json:"version"`
		AccountID string   `json:"account_id"`
		Scopes    []string `json:"scopes"`
	}
	if json.Unmarshal(data, &got) != nil || got.Connected != connected || got.State != state || got.Version != version || (account && got.AccountID != "fixture-subject") || got.Scopes == nil || !equalStrings(got.Scopes, scopes) {
		t.Fatalf("OAuth2 status=%s", data)
	}
}

func assertRegisteredOAuth2Completion(t *testing.T, response *http.Response) {
	t.Helper()
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("OAuth2 completion status=%d cache=%q err=%v body=%s", response.StatusCode, response.Header.Get("Cache-Control"), err, data)
	}
	assertMetadataOnlyOAuth2Body(t, data)
	var got struct {
		Connected bool     `json:"connected"`
		AccountID string   `json:"account_id"`
		Scopes    []string `json:"scopes"`
	}
	if json.Unmarshal(data, &got) != nil || !got.Connected || got.AccountID != "fixture-subject" || !equalStrings(got.Scopes, []string{"account"}) {
		t.Fatalf("OAuth2 completion=%s", data)
	}
}

func assertMetadataOnlyOAuth2Response(t *testing.T, response *http.Response, want int) {
	t.Helper()
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	response.Body.Close()
	if err != nil || response.StatusCode != want {
		t.Fatalf("OAuth2 response status=%d want=%d err=%v body=%s", response.StatusCode, want, err, data)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("OAuth2 response cache=%q", response.Header.Get("Cache-Control"))
	}
	assertMetadataOnlyOAuth2Body(t, data)
}

type oauth2FixtureStatsSnapshot struct {
	Authorize int `json:"Authorize"`
	Token     int `json:"Token"`
	UserInfo  int `json:"UserInfo"`
}

func readOAuth2FixtureStats(t *testing.T, client *http.Client, base string) oauth2FixtureStatsSnapshot {
	t.Helper()
	r := do(t, client, http.MethodGet, base+"/stats", nil, nil)
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("provider stats status=%d", r.StatusCode)
	}
	var stats oauth2FixtureStatsSnapshot
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	return stats
}

func assertMetadataOnlyOAuth2Body(t *testing.T, data []byte) {
	t.Helper()
	for _, forbidden := range []string{"access_token", "refresh_token", "client_secret", "secret_envelope"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("OAuth2 response exposed %q", forbidden)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

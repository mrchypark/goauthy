package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// HTTP acceptance plus opt-in Chromium approval. Backoffice's session-bound
// callback/state implementation is verified separately by the consuming app.
func testUseHandoffLive(t *testing.T, owner *http.Client, base string, cookie *http.Cookie, headers map[string]string, collection, connection, consumer string) {
	t.Helper()
	ensureResourcePermissionScope(t, owner, base, headers, "goauthy.connections.write")
	id := "handoff-requester-" + randomManagedUIID(t)
	const callback = "https://rp.example.test/use-grant"
	clientBody, _ := json.Marshal(map[string]any{"id": id, "confidential": false, "redirect_uris": []string{callback}, "audience": []string{useGrantResource}, "scopes": []string{"goauthy.connections.write"}, "default_scopes": []string{"goauthy.connections.write"}, "enabled_flows": []string{"authorization_code"}})
	r := do(t, owner, http.MethodPost, base+"/auth/v1/clients", strings.NewReader(string(clientBody)), headers)
	r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatalf("handoff requester create=%d", r.StatusCode)
	}
	t.Cleanup(func() {
		r := do(t, owner, http.MethodDelete, base+"/auth/v1/clients/"+id, nil, sessionHeader(headers, "If-Match", `"1"`))
		r.Body.Close()
		if r.StatusCode != 204 {
			t.Errorf("handoff requester cleanup=%d", r.StatusCode)
		}
	})
	token := issueGrantResourceToken(t, owner, base, id, useGrantResource, "goauthy.connections.write")
	bearer := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}
	create := func(returnURI, state string, want int) (string, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"collection_id": collection, "connection_id": connection, "consumer_client_id": consumer, "mode": "proxy", "purpose": "handoff-acceptance", "expires_at_unix_ms": time.Now().Add(time.Hour).UnixMilli(), "return_uri": returnURI, "state": state})
		r := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-handoffs", strings.NewReader(string(body)), bearer)
		defer r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("handoff create=%d want=%d", r.StatusCode, want)
		}
		if want != 201 {
			return "", ""
		}
		var start struct {
			ID        string `json:"id"`
			ReviewURI string `json:"review_uri"`
			Review    struct {
				Grant struct {
					ID       string `json:"id"`
					Consumer string `json:"consumer_client_id"`
					Digest   string `json:"connector_digest"`
				} `json:"grant"`
			} `json:"review"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&start) != nil || start.ID == "" || start.ReviewURI != base+"/account/connection-handoffs/"+start.ID || start.Review.Grant.ID != "" || start.Review.Grant.Consumer != consumer || start.Review.Grant.Digest == "" {
			t.Fatal("handoff start metadata mismatch")
		}
		return start.ReviewURI, start.Review.Grant.Digest
	}
	create("https://unregistered.example/callback", strings.Repeat("A", 32), 404)
	create(callback+"?state=bad", strings.Repeat("A", 32), 400)
	create(callback, "short", 400)
	state := strings.Repeat("B", 32)
	before := mustGrantList(t, owner, base+"/auth/v1/account/connections/"+collection+"/"+connection, headers)
	reviewURI, digest := create(callback, state, 201)
	reviewURI = strings.Replace(reviewURI, "/account/connection-handoffs/", "/auth/v1/account/connection-handoffs/", 1)
	after := mustGrantList(t, owner, base+"/auth/v1/account/connections/"+collection+"/"+connection, headers)
	if string(before) != string(after) {
		t.Fatal("handoff proposal created implicit grant")
	}
	r = do(t, newBrowserClient(t), http.MethodGet, reviewURI, nil, bearer)
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("Bearer owner review=%d", r.StatusCode)
	}
	r = do(t, owner, http.MethodGet, reviewURI, nil, nil)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("owner review=%d", r.StatusCode)
	}
	complete := func(uri, body string, want int) string {
		t.Helper()
		r := do(t, owner, http.MethodPost, uri, strings.NewReader(body), headers)
		defer r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("handoff complete=%d want=%d", r.StatusCode, want)
		}
		if want != 200 {
			return ""
		}
		var result struct {
			ReturnURI string `json:"return_uri"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&result) != nil || result.ReturnURI == "" {
			t.Fatal("handoff return missing")
		}
		return result.ReturnURI
	}
	complete(reviewURI, `{"approve":true,"connector_digest":"`+strings.Repeat("A", 43)+`"}`, 409)
	returnURI := complete(reviewURI, `{"approve":true,"connector_digest":"`+digest+`"}`, 200)
	u, err := url.Parse(returnURI)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != callback || u.Query().Get("state") != state || u.Query().Get("grant_id") == "" || len(u.Query()) != 2 {
		t.Fatal("approved return mismatch")
	}
	grantID := u.Query().Get("grant_id")
	complete(reviewURI, `{"approve":true,"connector_digest":"`+digest+`"}`, 404)
	r = do(t, owner, http.MethodDelete, base+"/auth/v1/account/connections/"+collection+"/"+connection+"/grants/"+grantID, nil, sessionHeader(headers, "If-Match", `"1"`))
	r.Body.Close()
	if r.StatusCode != 204 {
		t.Fatalf("handoff grant revoke=%d", r.StatusCode)
	}
	deniedURI, _ := create(callback, strings.Repeat("C", 32), 201)
	deniedURI = strings.Replace(deniedURI, "/account/connection-handoffs/", "/auth/v1/account/connection-handoffs/", 1)
	u, err = url.Parse(complete(deniedURI, `{"approve":false}`, 200))
	if err != nil || u.Query().Get("state") != strings.Repeat("C", 32) || u.Query().Get("error") != "access_denied" || u.Query().Get("grant_id") != "" {
		t.Fatal("denied return mismatch")
	}
	complete(deniedURI, `{"approve":false}`, 404)
	pageURI, _ := create(callback, strings.Repeat("D", 32), 201)
	t.Run("cold-login", func(t *testing.T) {
		testHandoffColdLogin(t, owner, base, pageURI, headers, collection, connection)
	})
	if os.Getenv("GOAUTHY_E2E_HANDOFF_UI") == "1" {
		t.Run("browser", func(t *testing.T) {
			testConnectionHandoffUI(t, owner, base, cookie, headers, collection, connection, func(state string) (string, string) { return create(callback, state, 201) })
		})
	}
}

func testHandoffColdLogin(t *testing.T, owner *http.Client, base, reviewURI string, headers map[string]string, collection, connection string) {
	t.Helper()
	grantPath := base + "/auth/v1/account/connections/" + collection + "/" + connection
	before := mustGrantList(t, owner, grantPath, headers)
	cold := newBrowserClient(t)
	r := do(t, cold, http.MethodGet, reviewURI, nil, map[string]string{"Sec-Fetch-Site": "cross-site"})
	r.Body.Close()
	loginURI := r.Header.Get("Location")
	if r.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loginURI, base+"/account/connection-login?handoff_id=") {
		t.Fatalf("cold navigation=%d", r.StatusCode)
	}
	r = do(t, cold, http.MethodGet, loginURI, nil, nil)
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	r.Body.Close()
	interaction, iok := hiddenInputValue(string(body), "interaction")
	csrf, cok := hiddenInputValue(string(body), "csrf_token")
	if err != nil || r.StatusCode != 200 || !iok || !cok {
		t.Fatalf("cold login form=%d", r.StatusCode)
	}
	_, _, user, password, _ := browserE2EConfig(t)
	form := url.Values{"interaction": {interaction}, "csrf_token": {csrf}, "username": {user}, "password": {password}}
	r = do(t, cold, http.MethodPost, base+"/account/connection-login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": base})
	r.Body.Close()
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != reviewURI {
		t.Fatalf("cold login return=%d", r.StatusCode)
	}
	r = do(t, cold, http.MethodGet, reviewURI, nil, nil)
	body, err = io.ReadAll(io.LimitReader(r.Body, 32<<10))
	r.Body.Close()
	csrf, cok = hiddenInputValue(string(body), "csrf_token")
	if err != nil || r.StatusCode != 200 || !cok || !strings.Contains(string(body), "Review service access") {
		t.Fatalf("cold review=%d", r.StatusCode)
	}
	if after := mustGrantList(t, owner, grantPath, headers); string(after) != string(before) {
		t.Fatal("login implicitly granted access")
	}
	deny := url.Values{"decision": {"deny"}, "csrf_token": {csrf}}
	r = do(t, cold, http.MethodPost, reviewURI, strings.NewReader(deny.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": base})
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("cold explicit deny=%d", r.StatusCode)
	}
	if after := mustGrantList(t, owner, grantPath, headers); string(after) != string(before) {
		t.Fatal("denial created grant")
	}
}

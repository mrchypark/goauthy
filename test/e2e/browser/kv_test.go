package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

type kvE2EState struct {
	CookieName       string `json:"cookie_name"`
	CookieValue      string `json:"cookie_value"`
	CSRF             string `json:"csrf"`
	Namespace        string `json:"namespace"`
	RenamedNamespace string `json:"renamed_namespace"`
	AccessID         string `json:"access_id"`
	AccessSecret     string `json:"access_secret"`
	RotatedSecret    string `json:"rotated_secret"`
}

// TestKVAPI is two phase: initial leaves data for restart, post-restart verifies every node then cleans up.
func TestKVAPI(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_KV") != "1" {
		t.Skip("set GOAUTHY_E2E_KV=1 to run KV E2E")
	}
	raw := strings.Trim(os.Getenv("GOAUTHY_E2E_KV_URLS"), ",")
	urls := strings.Split(raw, ",")
	if (len(urls) != 1 && len(urls) != 3) || raw == "" {
		t.Fatal("GOAUTHY_E2E_KV_URLS must contain one or three URLs")
	}
	for i := range urls {
		urls[i] = strings.TrimRight(strings.TrimSpace(urls[i]), "/")
	}
	user, pass := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	if user == "" || pass == "" {
		t.Fatal("browser credentials are required")
	}
	statePath := os.Getenv("GOAUTHY_E2E_KV_STATE")
	if statePath == "" {
		t.Fatal("GOAUTHY_E2E_KV_STATE must name a private fixture in the harness temp directory")
	}
	switch os.Getenv("GOAUTHY_E2E_KV_PHASE") {
	case "initial":
		kvInitial(t, urls, user, pass, statePath)
	case "post-restart", "state":
		kvPost(t, urls, statePath, os.Getenv("GOAUTHY_E2E_KV_PHASE") == "state")
	default:
		t.Fatal("set GOAUTHY_E2E_KV_PHASE to initial or post-restart")
	}
}

func kvInitial(t *testing.T, urls []string, user, pass, statePath string) {
	status(t, newBrowserClient(t), http.MethodGet, urls[0]+"/auth/v1/kv/ns", "", nil, http.StatusUnauthorized)
	client := newBrowserClient(t)
	loginBase := urls[min(1, len(urls)-1)]
	_, cookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, urls[0], defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "kv-e2e-initial-state", "kv-e2e-nonce"), urls[0], loginBase, user, pass, "kv-e2e-initial-state")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	admin := kvAdminHeaders(csrf)
	ns := "e2e-kv-" + strings.ToLower(cookie.Value[:8])
	renamed := ns + "-renamed"
	jsonStatus(t, client, http.MethodPost, urls[0]+"/auth/v1/kv/ns", map[string]any{"name": ns}, nil, http.StatusUnauthorized)
	status(t, client, http.MethodGet, urls[0]+"/auth/v1/kv/ns", "", kvBearer("invalid", "invalid"), http.StatusUnauthorized)
	status(t, client, http.MethodGet, urls[0]+"/auth/v1/kv/pub/default/private", "", nil, http.StatusUnauthorized)
	jsonStatus(t, client, http.MethodPost, urls[0]+"/auth/v1/kv/ns", map[string]any{"name": ns, "public": true}, admin, http.StatusOK)
	var access struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	jsonDecode(t, client, http.MethodPost, loginBase+"/auth/v1/kv/ns/"+url.PathEscape(ns)+"/access", map[string]any{"enabled": true, "name": "e2e"}, admin, http.StatusCreated, &access)
	if access.ID == "" || access.Secret == "" {
		t.Fatal("access response missing credentials")
	}
	auth := kvBearer(access.ID, access.Secret)
	values := kvFixtureValues()
	for key, value := range values {
		jsonStatus(t, client, http.MethodPut, urls[0]+"/auth/v1/kv/keys", map[string]any{"key": key, "value": value, "encrypted": true}, auth, http.StatusOK)
	}
	// Rename only after encrypted rows exist, so the gate proves AAD identity
	// survives the namespace cascade, not merely empty namespace metadata.
	jsonStatus(t, client, http.MethodPut, loginBase+"/auth/v1/kv/ns/"+url.PathEscape(ns), map[string]any{"name": renamed, "public": true}, admin, http.StatusOK)
	jsonStatus(t, client, http.MethodPut, loginBase+"/auth/v1/kv/keys", map[string]any{"key": "string", "value": "repeated-write"}, auth, http.StatusOK)
	jsonStatus(t, client, http.MethodPut, loginBase+"/auth/v1/kv/keys", map[string]any{"key": "string", "value": "value"}, auth, http.StatusOK)
	for _, base := range urls {
		kvAssertValues(t, client, base, renamed, auth, values)
		jsonStatus(t, client, http.MethodGet, base+"/auth/v1/kv/ns/"+renamed+"/values?limit=1&search=object", nil, admin, http.StatusOK)
		jsonStatus(t, client, http.MethodGet, base+"/auth/v1/kv/ns/"+renamed+"/access", nil, admin, http.StatusOK)
		status(t, client, http.MethodGet, base+"/auth/v1/kv/keys?namespace=default", "", auth, http.StatusBadRequest)
	}
	// Exercise both admin value methods and both deletion surfaces.
	jsonStatus(t, client, http.MethodPost, loginBase+"/auth/v1/kv/ns/"+renamed+"/values", map[string]any{"key": "temporary", "value": 1}, admin, http.StatusOK)
	jsonStatus(t, client, http.MethodPut, loginBase+"/auth/v1/kv/ns/"+renamed+"/values", map[string]any{"key": "temporary", "value": 2, "encrypted": true}, admin, http.StatusOK)
	jsonStatus(t, client, http.MethodDelete, urls[0]+"/auth/v1/kv/ns/"+renamed+"/values/temporary", nil, admin, http.StatusOK)
	jsonStatus(t, client, http.MethodPut, loginBase+"/auth/v1/kv/keys", map[string]any{"key": "temporary", "value": 3}, auth, http.StatusOK)
	jsonStatus(t, client, http.MethodDelete, urls[0]+"/auth/v1/kv/keys/temporary", nil, auth, http.StatusOK)
	status(t, client, http.MethodGet, loginBase+"/auth/v1/kv/keys/temporary", "", auth, http.StatusNotFound)
	jsonStatus(t, client, http.MethodPut, loginBase+"/auth/v1/kv/ns/"+renamed+"/access/"+access.ID, map[string]any{"enabled": false}, admin, http.StatusOK)
	for _, base := range urls {
		status(t, client, http.MethodGet, base+"/auth/v1/kv/test", "", auth, http.StatusUnauthorized)
	}
	jsonStatus(t, client, http.MethodPut, loginBase+"/auth/v1/kv/ns/"+url.PathEscape(renamed)+"/access/"+access.ID, map[string]any{"enabled": true, "name": "renamed"}, admin, http.StatusOK)
	var rotated struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	jsonDecode(t, client, http.MethodPost, urls[len(urls)-1]+"/auth/v1/kv/ns/"+url.PathEscape(renamed)+"/access/"+access.ID+"/secret", nil, admin, http.StatusOK, &rotated)
	if rotated.Secret == "" || rotated.Secret == access.Secret {
		t.Fatal("secret was not rotated")
	}
	var extra struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	jsonDecode(t, client, http.MethodPost, urls[0]+"/auth/v1/kv/ns/"+renamed+"/access", map[string]any{"enabled": true}, admin, http.StatusCreated, &extra)
	jsonStatus(t, client, http.MethodDelete, loginBase+"/auth/v1/kv/ns/"+renamed+"/access/"+extra.ID, nil, admin, http.StatusOK)
	for _, base := range urls {
		status(t, client, http.MethodGet, base+"/auth/v1/kv/test", "", auth, http.StatusUnauthorized)
		status(t, client, http.MethodGet, base+"/auth/v1/kv/test", "", kvBearer(extra.ID, extra.Secret), http.StatusUnauthorized)
	}
	state := kvE2EState{cookie.Name, cookie.Value, csrf, "default", renamed, access.ID, access.Secret, rotated.Secret}
	b, _ := json.Marshal(state)
	if err := os.WriteFile(statePath, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func kvPost(t *testing.T, urls []string, statePath string, stateOnly bool) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var s kvE2EState
	if err = json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	client := clientWithCookie(t, urls[0], &http.Cookie{Name: s.CookieName, Value: s.CookieValue})
	admin := kvAdminHeaders(s.CSRF)
	old, current := kvBearer(s.AccessID, s.AccessSecret), kvBearer(s.AccessID, s.RotatedSecret)
	for _, base := range urls {
		jsonStatus(t, client, http.MethodGet, base+"/auth/v1/kv/ns", nil, admin, http.StatusOK)
		kvAssertValues(t, client, base, s.RenamedNamespace, current, kvFixtureValues())
		status(t, client, http.MethodGet, base+"/auth/v1/kv/keys/object", "", old, http.StatusUnauthorized)
		status(t, client, http.MethodGet, base+"/auth/v1/kv/keys/object", "", map[string]string{"Authorization": "Bearer bad"}, http.StatusUnauthorized)
	}
	if stateOnly {
		return
	}
	jsonStatus(t, client, http.MethodDelete, urls[0]+"/auth/v1/kv/ns/"+url.PathEscape(s.RenamedNamespace), nil, admin, http.StatusOK)
	for _, base := range urls {
		status(t, client, http.MethodGet, base+"/auth/v1/kv/pub/"+url.PathEscape(s.RenamedNamespace)+"/object", "", nil, http.StatusNotFound)
		status(t, client, http.MethodGet, base+"/auth/v1/kv/keys/object", "", current, http.StatusUnauthorized)
	}
}

func kvAssertValues(t *testing.T, c *http.Client, base, ns string, auth map[string]string, values map[string]json.RawMessage) {
	for key, want := range values {
		r := do(t, c, http.MethodGet, base+"/auth/v1/kv/keys/"+url.PathEscape(key), nil, auth)
		got, err := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("get %s status=%d", key, r.StatusCode)
		}
		var a, b any
		if json.Unmarshal(got, &a) != nil || json.Unmarshal(want, &b) != nil {
			t.Fatal("invalid JSON value")
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("value %s=%s want=%s", key, got, want)
		}
	}
	status(t, c, http.MethodGet, base+"/auth/v1/kv/pub/"+url.PathEscape(ns)+"/string", "", nil, http.StatusOK)
	status(t, c, http.MethodGet, base+"/auth/v1/kv/pub/"+url.PathEscape(ns)+"/object", "", nil, http.StatusOK)
	status(t, c, http.MethodGet, base+"/auth/v1/kv/keys?search=string", "", auth, http.StatusOK)
	var keys []string
	jsonDecode(t, c, http.MethodGet, base+"/auth/v1/kv/keys?search=object&limit=1", nil, auth, http.StatusOK, &keys)
	if len(keys) != 1 || keys[0] != "object" {
		t.Fatalf("filtered keys=%v", keys)
	}
	var all []struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	jsonDecode(t, c, http.MethodGet, base+"/auth/v1/kv/values", nil, auth, http.StatusOK, &all)
	if len(all) != 6 {
		t.Fatalf("value count=%d", len(all))
	}
	var identity struct {
		ID        string `json:"id"`
		Namespace string `json:"ns"`
	}
	jsonDecode(t, c, http.MethodGet, base+"/auth/v1/kv/test", nil, auth, http.StatusOK, &identity)
	if identity.ID == "" || identity.Namespace != ns {
		t.Fatalf("KV principal namespace=%q", identity.Namespace)
	}
}

func kvFixtureValues() map[string]json.RawMessage {
	return map[string]json.RawMessage{"null": json.RawMessage("null"), "bool": json.RawMessage("true"), "number": json.RawMessage("42.5"), "string": json.RawMessage(`"value"`), "array": json.RawMessage(`[1,"x"]`), "object": json.RawMessage(`{"ok":true}`)}
}

func kvAdminHeaders(csrf string) map[string]string {
	return map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
}
func kvBearer(id, secret string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + id + "$" + secret, "Content-Type": "application/json"}
}
func jsonStatus(t *testing.T, c *http.Client, method, endpoint string, value any, headers map[string]string, want int) {
	t.Helper()
	var body io.Reader
	if value != nil {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	r := do(t, c, method, endpoint, body, headers)
	r.Body.Close()
	if r.StatusCode != want {
		t.Fatalf("%s %s status=%d want=%d", method, endpoint, r.StatusCode, want)
	}
}
func jsonDecode(t *testing.T, c *http.Client, method, endpoint string, value any, headers map[string]string, want int, out any) {
	t.Helper()
	var body io.Reader
	if value != nil {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	r := do(t, c, method, endpoint, body, headers)
	defer r.Body.Close()
	if r.StatusCode != want {
		t.Fatalf("%s %s status=%d want=%d", method, endpoint, r.StatusCode, want)
	}
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing KV response security headers")
	}
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
func status(t *testing.T, c *http.Client, method, endpoint, body string, headers map[string]string, want int) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	response := do(t, c, method, endpoint, r, headers)
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("%s %s status=%d want=%d", method, endpoint, response.StatusCode, want)
	}
}

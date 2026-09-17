package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestAdminIndexHA checks the browser-only admin landing page through all
// three independently forwarded pods, including session replication.
func TestAdminIndexHA(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_HA") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_HA=1 to run admin HA E2E")
	}
	raw := strings.Split(os.Getenv("GOAUTHY_E2E_ADMIN_HA_URLS"), ",")
	if len(raw) != 3 {
		t.Fatal("GOAUTHY_E2E_ADMIN_HA_URLS must contain three URLs")
	}
	for i := range raw {
		raw[i] = strings.TrimRight(strings.TrimSpace(raw[i]), "/")
	}
	username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	if username == "" || password == "" {
		t.Fatal("browser credentials are required")
	}
	anonymous := newBrowserClient(t)
	response := do(t, anonymous, http.MethodGet, raw[0]+"/auth/v1/admin", nil, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d", response.StatusCode)
	}
	client := newBrowserClient(t)
	initClient := newBrowserClient(t)
	initResponse := do(t, initClient, http.MethodGet, oidcAuthorizationURL(t, raw[0], defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "admin-index-init", "admin-index-init-nonce"), nil, nil)
	if initResponse.StatusCode != http.StatusOK {
		initResponse.Body.Close()
		t.Fatalf("init authorize status=%d", initResponse.StatusCode)
	}
	initResponse.Body.Close()
	initResponse = do(t, initClient, http.MethodGet, raw[0]+"/auth/v1/admin", nil, nil)
	initResponse.Body.Close()
	if initResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("init-session status=%d", initResponse.StatusCode)
	}
	var cookie *http.Cookie
	if os.Getenv("GOAUTHY_E2E_ADMIN_HA_PHASE") == "post-restart" {
		data, err := os.ReadFile(os.Getenv("GOAUTHY_E2E_ADMIN_HA_STATE_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		var state struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if json.Unmarshal(data, &state) != nil || state.Name == "" || state.Value == "" {
			t.Fatal("invalid persisted admin session")
		}
		cookie = &http.Cookie{Name: state.Name, Value: state.Value}
		for _, base := range raw {
			client = clientWithCookie(t, base, cookie)
			break
		}
	} else {
		_, cookie = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, raw[0], defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "admin-index-ha", "admin-index-ha-nonce"), raw[0], raw[1], username, password, "admin-index-ha")
		if path := os.Getenv("GOAUTHY_E2E_ADMIN_HA_STATE_FILE"); path != "" {
			data, _ := json.Marshal(struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}{cookie.Name, cookie.Value})
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, base := range raw {
		assertAdminIndex(t, client, base)
	}
	for _, tc := range []struct {
		name, header string
		url          string
	}{
		{"bearer", "Bearer invalid", raw[0] + "/auth/v1/admin"},
		{"api-key", "API-Key invalid", raw[1] + "/auth/v1/admin"},
		{"cross-site", "", raw[2] + "/auth/v1/admin"},
		{"query", "", raw[0] + "/auth/v1/admin?probe=1"},
	} {
		headers := map[string]string{"Sec-Fetch-Site": "same-origin"}
		if tc.name == "cross-site" {
			headers["Sec-Fetch-Site"] = "cross-site"
		}
		if tc.header != "" {
			headers["Authorization"] = tc.header
		}
		response := do(t, client, http.MethodGet, tc.url, nil, headers)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s status=%d", tc.name, response.StatusCode)
		}
	}
	if os.Getenv("GOAUTHY_E2E_ADMIN_HA_PHASE") != "post-restart" {
		t.Log("admin session remains active for pod replacement phase")
		return
	}
	stale := clientWithCookie(t, raw[0], cookie)
	confirm := do(t, client, http.MethodGet, raw[1]+"/oidc/logout?client_id=goauthy-dev&post_logout_redirect_uri="+url.QueryEscape(defaultPostLogoutRedirectURI), nil, nil)
	if confirm.StatusCode != http.StatusOK {
		confirm.Body.Close()
		t.Fatalf("logout confirmation status=%d", confirm.StatusCode)
	}
	token, ok := hiddenInputValue(readLimitedBody(t, confirm), "confirmation")
	confirm.Body.Close()
	if !ok {
		t.Fatal("logout confirmation token missing")
	}
	form := url.Values{"confirmation": {token}}
	response = do(t, client, http.MethodPost, raw[2]+"/oidc/logout", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status=%d", response.StatusCode)
	}
	for _, base := range raw {
		response = do(t, stale, http.MethodGet, base+"/auth/v1/admin", nil, nil)
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked session status=%d pod=%s", response.StatusCode, base)
		}
	}
}

func assertAdminIndex(t *testing.T, client *http.Client, base string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/admin", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin index status=%d", response.StatusCode)
	}
	want := []string{"/auth/v1/admin/users", "/auth/v1/admin/roles", "/auth/v1/admin/groups", "/auth/v1/roles", "/auth/v1/groups", "/auth/v1/scopes", "/auth/v1/users/attr", "/auth/v1/users", "/auth/v1/api_keys"}
	links := regexp.MustCompile(`href="([^"]+)"`).FindAllStringSubmatch(string(body), -1)
	got := make([]string, 0, len(links))
	for _, match := range links {
		got = append(got, match[1])
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("admin links=%v want=%v", got, want)
	}
	for name, value := range map[string]string{"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Content-Type": "text/html; charset=utf-8"} {
		if got := response.Header.Get(name); got != value {
			t.Fatalf("%s=%q want %q", name, got, value)
		}
	}
}

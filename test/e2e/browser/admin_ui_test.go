package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestAdminUIHTTPAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_UI") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_UI=1 to run admin UI E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "admin-ui-http")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	for _, base := range nodes {
		for _, path := range []string{"/auth/v1/admin/users", "/auth/v1/admin/roles", "/auth/v1/admin/groups"} {
			r := do(t, newBrowserClient(t), http.MethodGet, base+path, nil, nil)
			body, readErr := io.ReadAll(io.LimitReader(r.Body, 128<<10))
			r.Body.Close()
			if r.StatusCode != http.StatusUnauthorized || readErr != nil || len(body) != 0 {
				t.Fatalf("anonymous %s status=%d body=%q", path, r.StatusCode, body)
			}
			r = do(t, client, http.MethodGet, base+path, nil, map[string]string{"Authorization": "Bearer malformed"})
			r.Body.Close()
			if r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("authorization fallback %s status=%d", path, r.StatusCode)
			}
			r = do(t, client, http.MethodGet, base+path, nil, map[string]string{"Sec-Fetch-Site": "cross-site"})
			r.Body.Close()
			if r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("cross-site %s status=%d", path, r.StatusCode)
			}
			r = do(t, client, http.MethodGet, base+path, nil, nil)
			body, readErr = io.ReadAll(io.LimitReader(r.Body, 128<<10))
			r.Body.Close()
			if r.StatusCode != http.StatusOK || readErr != nil || !strings.Contains(string(body), "<!doctype html>") {
				t.Fatalf("admin UI %s status=%d err=%v", path, r.StatusCode, readErr)
			}
			if r.Header.Get("Content-Type") != "text/html; charset=utf-8" || r.Header.Get("Content-Security-Policy") == "" || r.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("insecure UI headers %s: %#v", path, r.Header)
			}
		}
		for path, mime := range map[string]string{"/auth/v1/admin/app.js": "text/javascript; charset=utf-8", "/auth/v1/admin/admin.css": "text/css; charset=utf-8"} {
			r := do(t, client, http.MethodGet, base+path, nil, nil)
			body, readErr := io.ReadAll(io.LimitReader(r.Body, 256<<10))
			r.Body.Close()
			if r.StatusCode != http.StatusOK || readErr != nil || len(body) == 0 || r.Header.Get("Content-Type") != mime {
				t.Fatalf("asset %s status=%d mime=%q", path, r.StatusCode, r.Header.Get("Content-Type"))
			}
		}
		r := do(t, client, http.MethodGet, base+"/auth/v1/admin/csrf", nil, nil)
		var out map[string]string
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&out); err != nil {
			r.Body.Close()
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK || browsersession.ValidateCSRFToken(cookie.Value, out["token"]) != nil || strings.Contains(r.Header.Get("Set-Cookie"), cookie.Value) {
			t.Fatalf("invalid csrf response status=%d", r.StatusCode)
		}
		csrf = out["token"]
	}

	// Exercise the same CSRF-bearing role/group APIs used by the UI.
	roleName := "admin-ui-role-http"
	groupName := "admin-ui-group-http"
	role := rbacCreate(t, client, primary, "roles", roleName, map[string]any{"source": "admin-ui"}, csrf)
	group := rbacCreate(t, client, secondary, "groups", groupName, map[string]any{"source": "admin-ui"}, csrf)
	for _, base := range nodes {
		rbacAssertListed(t, client, base, "roles", rbacEntity{Name: roleName, Meta: map[string]any{"source": "admin-ui"}})
		rbacAssertListed(t, client, base, "groups", rbacEntity{Name: groupName, Meta: map[string]any{"source": "admin-ui"}})
	}
	for _, base := range []string{primary} {
		r := do(t, client, http.MethodDelete, base+"/auth/v1/roles/"+role.ID, nil, rbacMutationHeaders(csrf))
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("role delete node=%s status=%d", base, r.StatusCode)
		}
		r = do(t, client, http.MethodDelete, base+"/auth/v1/groups/"+group.ID, nil, rbacMutationHeaders(csrf))
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("group delete node=%s status=%d", base, r.StatusCode)
		}
	}
	for _, base := range nodes {
		rbacAssertAbsent(t, client, base, "roles", roleName)
		rbacAssertAbsent(t, client, base, "groups", groupName)
	}
}

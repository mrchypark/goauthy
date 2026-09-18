package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The observing application and execution consumer are deliberately different.
func grantStatusObserver(t *testing.T, owner *http.Client, base string, headers map[string]string, collection, connection, grant, consumer string) func(bool) {
	t.Helper()
	ensureResourcePermissionScope(t, owner, base, headers, "goauthy.connections.read")
	id := "grant-observer-" + randomManagedUIID(t)
	body, _ := json.Marshal(map[string]any{
		"id": id, "confidential": false, "redirect_uris": []string{"https://rp.example.test/use-grant"},
		"audience": []string{useGrantResource}, "scopes": []string{"goauthy.connections.read"},
		"default_scopes": []string{"goauthy.connections.read"}, "enabled_flows": []string{"authorization_code"},
	})
	r := do(t, owner, http.MethodPost, base+"/auth/v1/clients", strings.NewReader(string(body)), headers)
	r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("observer create=%d", r.StatusCode)
	}
	t.Cleanup(func() {
		r := do(t, owner, http.MethodDelete, base+"/auth/v1/clients/"+id, nil, sessionHeader(headers, "If-Match", `"1"`))
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("observer cleanup=%d", r.StatusCode)
		}
	})
	token := issueGrantResourceToken(t, owner, base, id, useGrantResource, "goauthy.connections.read")
	noAudience := issueGrantResourceToken(t, owner, base, id, "", "goauthy.connections.read")
	path := base + "/auth/v1/connections/" + collection + "/" + connection + "/grants/" + grant
	for _, tc := range []struct {
		suffix, token string
		status        int
	}{
		{"", "", http.StatusUnauthorized}, {"", noAudience, http.StatusUnauthorized},
		{"?", token, http.StatusUnauthorized}, {"-missing", token, http.StatusNotFound},
	} {
		r := do(t, newBrowserClient(t), http.MethodGet, path+tc.suffix, nil, map[string]string{"Authorization": "Bearer " + tc.token})
		r.Body.Close()
		if r.StatusCode != tc.status {
			t.Fatalf("grant observer boundary=%d want=%d", r.StatusCode, tc.status)
		}
	}
	// Read permission never grants permission to invoke a connector.
	assertGrantInvokeStatus(t, base, grant, token, `{"operation":"account"}`, http.StatusUnauthorized)
	return func(revoked bool) {
		t.Helper()
		r := do(t, newBrowserClient(t), http.MethodGet, path, nil, map[string]string{"Authorization": "Bearer " + token})
		defer r.Body.Close()
		data, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
		if err != nil || r.StatusCode != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("grant observer status=%d err=%v", r.StatusCode, err)
		}
		var status struct {
			Grant struct {
				ID         string `json:"id"`
				Consumer   string `json:"consumer_client_id"`
				Connection string `json:"connection_id"`
				Generation string `json:"generation"`
				Revoked    bool   `json:"revoked"`
			} `json:"grant"`
			Generation string `json:"connection_generation"`
		}
		if json.Unmarshal(data, &status) != nil || status.Grant.ID != grant || status.Grant.Consumer != consumer || status.Grant.Consumer == id || status.Grant.Connection != connection || status.Generation == "" || status.Generation != status.Grant.Generation || status.Grant.Revoked != revoked {
			t.Fatal("grant observer metadata mismatch")
		}
		if strings.Contains(string(data), "e2e-bound-api-key") || strings.Contains(string(data), "e2e-rotated-key") {
			t.Fatal("grant status leaked credential")
		}
	}
}

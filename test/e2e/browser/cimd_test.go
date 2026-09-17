package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestCIMDMetadataDocumentAcrossPods verifies the deployed, opt-in URL client
// boundary. The fixture admin API is intentionally state-based: no timer or
// retry is needed to prove the first-writer cache behavior.
func TestCIMDMetadataDocumentAcrossPods(t *testing.T) {
	primary, secondary, clientID, redirectURI, adminURL := cimdBrowserE2EConfig(t)
	admin := noRedirectClient(t, nil)
	fixtureReset(t, admin, adminURL)

	assertCIMDDiscovery(t, primary)
	assertCIMDLoginRequired(t, primary, clientID, redirectURI, "cimd-first")
	state := fixtureState(t, admin, adminURL)
	if state.Requests != 1 || state.Mode != "valid" {
		t.Fatalf("first CIMD lookup state=%+v, want one valid document fetch", state)
	}

	fixtureDocument(t, admin, adminURL, "invalid")
	assertCIMDLoginRequired(t, secondary, clientID, redirectURI, "cimd-shared-cache")
	state = fixtureState(t, admin, adminURL)
	if state.Requests != 1 || state.Mode != "invalid" {
		t.Fatalf("second pod refetched mutated CIMD document: %+v", state)
	}
	if username, password := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME"), os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD"); username != "" && password != "" {
		client := newBrowserClient(t)
		verifier := pkceVerifier(t)
		code, _ := loginForAuthorizationURL(t, client, authorizationURLForClient(primary, clientID, redirectURI, pkceChallenge(verifier), "cimd-code", "goauthy.read"), primary, secondary, username, password, "cimd-code")
		tokens := exchangePublicCode(t, client, secondary, clientID, redirectURI, code, verifier)
		if tokens.AccessToken == "" || tokens.RefreshToken != "" || tokens.IDToken != "" {
			t.Fatal("CIMD public authorization-code exchange returned unexpected tokens")
		}
		if state = fixtureState(t, admin, adminURL); state.Requests != 1 {
			t.Fatalf("CIMD code/token flow refetched mutated metadata: %+v", state)
		}
	}

	for _, tc := range []struct {
		name        string
		clientID    string
		wantCounter func(cimdFixtureState) int
	}{
		{name: "document ID mismatch", clientID: cimdFixtureClientID(t, clientID, "/mismatch"), wantCounter: func(state cimdFixtureState) int { return state.Negative.Mismatch }},
		{name: "malformed document", clientID: cimdFixtureClientID(t, clientID, "/invalid"), wantCounter: func(state cimdFixtureState) int { return state.Negative.Invalid }},
		{name: "redirect to private target", clientID: cimdFixtureClientID(t, clientID, "/redirect-private"), wantCounter: func(state cimdFixtureState) int { return state.Negative.RedirectPrivate }},
		{name: "private literal", clientID: "https://127.0.0.1/good", wantCounter: func(cimdFixtureState) int { return 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixtureReset(t, admin, adminURL)
			assertCIMDNoClientFailure(t, primary, tc.clientID, redirectURI)
			state := fixtureState(t, admin, adminURL)
			if got := tc.wantCounter(state); got != 1 && tc.clientID != "https://127.0.0.1/good" {
				t.Fatalf("%s fixture counter=%d state=%+v, want 1", tc.name, got, state)
			}
			if tc.clientID == "https://127.0.0.1/good" && state.Requests != 0 {
				t.Fatalf("private literal contacted fixture: %+v", state)
			}
			if state.Negative.Sentinel != 0 {
				t.Fatalf("%s reached private redirect sentinel: %+v", tc.name, state)
			}
		})
	}
}

type cimdFixtureState struct {
	Requests int    `json:"requests"`
	Mode     string `json:"mode"`
	Negative struct {
		Mismatch        int `json:"mismatch"`
		Invalid         int `json:"invalid"`
		RedirectPrivate int `json:"redirect_private"`
		Sentinel        int `json:"sentinel"`
	} `json:"negative"`
}

func cimdBrowserE2EConfig(t *testing.T) (primary, secondary, clientID, redirectURI, adminURL string) {
	t.Helper()
	primary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	clientID = os.Getenv("GOAUTHY_E2E_CIMD_CLIENT_ID")
	redirectURI = os.Getenv("GOAUTHY_E2E_CIMD_REDIRECT_URI")
	adminURL = strings.TrimRight(os.Getenv("GOAUTHY_E2E_CIMD_FIXTURE_ADMIN_URL"), "/")
	if primary == "" || secondary == "" || clientID == "" || redirectURI == "" || adminURL == "" {
		t.Skip("set both E2E URLs and GOAUTHY_E2E_CIMD_CLIENT_ID, GOAUTHY_E2E_CIMD_REDIRECT_URI, and GOAUTHY_E2E_CIMD_FIXTURE_ADMIN_URL to run CIMD browser E2E")
	}
	return primary, secondary, clientID, redirectURI, adminURL
}

func assertCIMDDiscovery(t *testing.T, baseURL string) {
	t.Helper()
	response := do(t, noRedirectClient(t, nil), http.MethodGet, baseURL+"/.well-known/oauth-authorization-server", nil, nil)
	defer response.Body.Close()
	var document struct {
		Supported bool `json:"client_id_metadata_document_supported"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&document) != nil || !document.Supported {
		t.Fatalf("CIMD discovery status=%d supported=%t", response.StatusCode, document.Supported)
	}
}

func assertCIMDLoginRequired(t *testing.T, baseURL, clientID, redirectURI, state string) {
	t.Helper()
	verifier := pkceVerifier(t)
	response := do(t, noRedirectClient(t, nil), http.MethodGet, authorizationURLForClient(baseURL, clientID, redirectURI, pkceChallenge(verifier), state, "goauthy.read")+"&prompt=none", nil, nil)
	assertLoginRequired(t, response, state)
}

func assertCIMDNoClientFailure(t *testing.T, baseURL, clientID, redirectURI string) {
	t.Helper()
	response := do(t, noRedirectClient(t, nil), http.MethodGet, authorizationURLForClient(baseURL, clientID, redirectURI, pkceChallenge(pkceVerifier(t)), "cimd-no-client", "goauthy.read")+"&prompt=none", nil, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || response.Header.Get("Location") != "" {
		t.Fatalf("untrusted CIMD client status=%d location=%q, want no-client failure without redirect", response.StatusCode, response.Header.Get("Location"))
	}
}

func cimdFixtureClientID(t *testing.T, clientID, path string) string {
	t.Helper()
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		t.Fatalf("invalid CIMD fixture client ID %q", clientID)
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = path, "", "", ""
	return u.String()
}

func fixtureReset(t *testing.T, client *http.Client, adminURL string) {
	t.Helper()
	fixturePost(t, client, adminURL+"/admin/reset", nil)
}

func fixtureDocument(t *testing.T, client *http.Client, adminURL, mode string) {
	t.Helper()
	body, err := json.Marshal(struct {
		Mode string `json:"mode"`
	}{Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	fixturePost(t, client, adminURL+"/admin/document", body)
}

func fixturePost(t *testing.T, client *http.Client, endpoint string, body []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("fixture POST %s status=%d", endpoint, response.StatusCode)
	}
}

func fixtureState(t *testing.T, client *http.Client, adminURL string) cimdFixtureState {
	t.Helper()
	response := do(t, client, http.MethodGet, adminURL+"/admin/state", nil, nil)
	defer response.Body.Close()
	var state cimdFixtureState
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&state) != nil {
		t.Fatalf("fixture state status=%d", response.StatusCode)
	}
	return state
}

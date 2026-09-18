package browser

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	scimChaosAdminEmail = "scim-chaos-admin@goauthy.e2e"
	scimChaosKeyEmail   = "scim-chaos-key@goauthy.e2e"
	scimChaosPassword   = "SCIM-Chaos-Delete-1A"
	scimChaosKeyName    = "scim-chaos-delete-key"
)

type scimChaosState struct {
	AdminSubject string `json:"admin_subject"`
	KeySubject   string `json:"key_subject"`
	KeySecret    string `json:"key_secret"`
	AdminToken   string `json:"admin_token,omitempty"`
	KeyToken     string `json:"key_token,omitempty"`
	AdminCookie  string `json:"admin_cookie,omitempty"`
	KeyCookie    string `json:"key_cookie,omitempty"`
}

// TestSCIMDeleteChaosAcrossThreePods covers both browser-admin and API-key
// deletion, final-admin protection, cross-pod session/token invalidation, and
// durable SCIM tombstone delivery. The surrounding script replaces a pod
// after deletion and performs the remote fixture convergence checks.
func TestSCIMDeleteChaosAcrossThreePods(t *testing.T) {
	phase := os.Getenv("GOAUTHY_E2E_SCIM_CHAOS_PHASE")
	if phase == "" {
		t.Skip("set GOAUTHY_E2E_SCIM_CHAOS_PHASE=create|delete|verify")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	stateFile := os.Getenv("GOAUTHY_E2E_SCIM_CHAOS_STATE_FILE")
	if stateFile == "" {
		t.Fatal("set GOAUTHY_E2E_SCIM_CHAOS_STATE_FILE")
	}
	switch phase {
	case "create":
		sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
		if sinkURL == "" {
			t.Fatal("set GOAUTHY_E2E_SMTP_SINK_URL")
		}
		mailbox := &http.Client{Timeout: 5 * time.Second}
		clearSMTPMailbox(t, mailbox, sinkURL)
		adminSubject := registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, scimChaosAdminEmail, scimChaosPassword, "scim_chaos_admin")
		keySubject := registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, scimChaosKeyEmail, scimChaosPassword, "scim_chaos_key")
		assertPasswordLogin(t, primary, secondary, scimChaosAdminEmail, "scim-chaos-admin-created", scimChaosPassword, http.StatusFound)
		assertPasswordLogin(t, primary, secondary, scimChaosKeyEmail, "scim-chaos-key-created", scimChaosPassword, http.StatusFound)
		admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
		group := rbacCreate(t, admin, primary, "groups", "scim-chaos-delete-group", nil, csrf)
		patchSCIMGroupMembership(t, admin, primary, adminSubject, group.Name, csrf)
		patchSCIMGroupMembership(t, admin, secondary, keySubject, group.Name, csrf)
		secret := createAdminAPIKey(t, admin, primary, csrf, scimChaosKeyName, []apiKeyAccess{{Group: "Users", AccessRights: []string{"read", "delete"}}})
		writeSCIMChaosState(t, stateFile, scimChaosState{AdminSubject: adminSubject, KeySubject: keySubject, KeySecret: secret})
	case "delete":
		state := readSCIMChaosState(t, stateFile)
		_, adminCookie, adminToken := loginSCIMChaosUser(t, primary, secondary, clientSecret, scimChaosAdminEmail, "chaos-admin-token")
		_, keyCookie, keyToken := loginSCIMChaosUser(t, primary, secondary, clientSecret, scimChaosKeyEmail, "chaos-key-token")
		admin, adminCSRF := rbacAuthenticatedClient(t, primary, secondary, username, password)
		deleteChaosUser(t, admin, secondary, state.AdminSubject, adminCSRF, "browser-admin delete")
		apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(state.KeySubject), nil, map[string]string{"Authorization": "API-Key " + state.KeySecret}, http.StatusNoContent, "API-key delete")
		assertUserDeleteSessionRejected(t, primary, adminCookie, "chaos-admin-session-primary")
		assertUserDeleteSessionRejected(t, secondary, adminCookie, "chaos-admin-session-secondary")
		assertUserDeleteSessionRejected(t, primary, keyCookie, "chaos-key-session-primary")
		assertUserDeleteSessionRejected(t, secondary, keyCookie, "chaos-key-session-secondary")
		assertUserInfoRejected(t, newBrowserClient(t), primary, http.MethodGet, "Bearer "+adminToken, "")
		assertUserInfoRejected(t, newBrowserClient(t), secondary, http.MethodGet, "Bearer "+adminToken, "")
		assertUserInfoRejected(t, newBrowserClient(t), primary, http.MethodGet, "Bearer "+keyToken, "")
		assertUserInfoRejected(t, newBrowserClient(t), secondary, http.MethodGet, "Bearer "+keyToken, "")
		apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, primary+"/auth/v1/users/bootstrap-admin", nil, map[string]string{"Authorization": "API-Key " + state.KeySecret}, http.StatusConflict, "final-admin guard")
		state.AdminToken, state.KeyToken = adminToken, keyToken
		state.AdminCookie, state.KeyCookie = adminCookie.Value, keyCookie.Value
		writeSCIMChaosState(t, stateFile, state)
	case "verify":
		state := readSCIMChaosState(t, stateFile)
		if state.AdminToken == "" || state.KeyToken == "" || state.AdminCookie == "" || state.KeyCookie == "" {
			t.Fatal("delete phase did not persist invalidation probes")
		}
		assertUserInfoRejected(t, newBrowserClient(t), primary, http.MethodGet, "Bearer "+state.AdminToken, "")
		assertUserInfoRejected(t, newBrowserClient(t), secondary, http.MethodGet, "Bearer "+state.KeyToken, "")
		assertUserDeleteSessionRejected(t, primary, &http.Cookie{Name: "goauthy_session", Value: state.AdminCookie}, "chaos-admin-session-after-replacement")
		assertUserDeleteSessionRejected(t, secondary, &http.Cookie{Name: "goauthy_session", Value: state.KeyCookie}, "chaos-key-session-after-replacement")
		apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, primary+"/auth/v1/users/bootstrap-admin", nil, map[string]string{"Authorization": "API-Key " + state.KeySecret}, http.StatusConflict, "final-admin guard after replacement")
	default:
		t.Fatalf("unknown chaos phase %q", phase)
	}
}

func loginSCIMChaosUser(t *testing.T, primary, secondary, clientSecret, email, state string) (*http.Client, *http.Cookie, string) {
	t.Helper()
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(verifier), email, scimChaosPassword, state)
	tokens := exchangeCode(t, client, primary, clientSecret, defaultRedirectURI, code, verifier)
	if tokens.AccessToken == "" {
		t.Fatal("chaos user did not receive access token")
	}
	return client, cookie, tokens.AccessToken
}

func deleteChaosUser(t *testing.T, client *http.Client, base, subject, csrf, label string) {
	t.Helper()
	response := do(t, client, http.MethodDelete, base+"/auth/v1/users/"+url.PathEscape(subject), nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("%s status=%d want=%d", label, response.StatusCode, http.StatusNoContent)
	}
}

func writeSCIMChaosState(t *testing.T, path string, state scimChaosState) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readSCIMChaosState(t *testing.T, path string) scimChaosState {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("invalid chaos state file: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state scimChaosState
	if json.Unmarshal(data, &state) != nil || state.AdminSubject == "" || state.KeySubject == "" || state.KeySecret == "" {
		t.Fatal("invalid chaos state")
	}
	return state
}

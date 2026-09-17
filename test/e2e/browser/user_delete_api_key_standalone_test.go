package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	standaloneAPIKeyDeleteEmail = "user-delete-api-key@goauthy.e2e"
	standaloneAPIKeyDeletePass  = "User-Delete-API-Key-1A"
)

// TestStandaloneUserDeletionAPIKey exercises the direct Users:delete API-key
// route alongside the browser-only self-delete boundary. The script supplies
// a fixed bootstrap key and SMTP/SCIM fixtures, so this test creates a real
// identity before deleting it and leaves a durable SCIM tombstone.
func TestStandaloneUserDeletionAPIKey(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_USER_DELETE_API_KEY") == "" {
		t.Skip("set GOAUTHY_E2E_USER_DELETE_API_KEY to run standalone API-key deletion E2E")
	}
	primary, secondary, adminUsername, adminPassword, _ := browserE2EConfig(t)
	sinkURL := os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL")
	if sinkURL == "" {
		t.Skip("set GOAUTHY_E2E_SMTP_SINK_URL to run standalone API-key deletion E2E")
	}
	mailbox := &http.Client{Timeout: 5 * time.Second}
	mode := os.Getenv("GOAUTHY_E2E_USER_DELETE_API_KEY_MODE")
	var target string
	switch mode {
	case "create":
		target = registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, standaloneAPIKeyDeleteEmail, standaloneAPIKeyDeletePass, "user_delete_api_key")
		writeStandaloneDeletionSubject(t, target)
		return
	case "delete":
		path := os.Getenv("GOAUTHY_E2E_USER_DELETE_SUBJECT_FILE")
		if path == "" {
			t.Fatal("GOAUTHY_E2E_USER_DELETE_SUBJECT_FILE is required in delete mode")
		}
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		target = string(bytes.TrimSpace(data))
		if target == "" {
			t.Fatal("standalone deletion subject file is empty")
		}
	default:
		target = registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, standaloneAPIKeyDeleteEmail, standaloneAPIKeyDeletePass, "user_delete_api_key")
		writeStandaloneDeletionSubject(t, target)
	}
	waitForStandaloneSCIMUser(t, target)

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, adminUsername, adminPassword)
	deleteEndpoint := secondary + "/auth/v1/users/" + url.PathEscape(target)
	apiKey := os.Getenv("GOAUTHY_E2E_USER_DELETE_API_KEY")

	// An API-key-shaped Authorization value takes precedence over a valid
	// browser cookie; malformed credentials never fall back to that cookie.
	apiKeyStatus(t, admin, http.MethodDelete, deleteEndpoint, nil, map[string]string{
		"Authorization":  "API-Key malformed",
		"Sec-Fetch-Site": "same-origin",
		"X-CSRF-Token":   csrf,
	}, http.StatusUnauthorized, "malformed API key does not fall back to browser")
	apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, secondary+"/auth/v1/users/"+url.PathEscape(target)+"/self/delete", nil, map[string]string{
		"Authorization": "API-Key " + apiKey,
	}, http.StatusUnauthorized, "API key cannot use self-delete")
	apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, deleteEndpoint, nil, map[string]string{
		"Authorization": "API-Key standalone-users$invalid",
	}, http.StatusUnauthorized, "invalid API key cannot delete")
	apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, deleteEndpoint, nil, map[string]string{
		"Authorization": "API-Key " + apiKey,
	}, http.StatusNoContent, "Users delete API key deletes target")

	assertPasswordLogin(t, primary, secondary, standaloneAPIKeyDeleteEmail, "api-key-deleted-user", standaloneAPIKeyDeletePass, http.StatusUnauthorized)
	apiKeyStatus(t, newBrowserClient(t), http.MethodDelete, secondary+"/auth/v1/users/bootstrap-admin", nil, map[string]string{
		"Authorization": "API-Key " + apiKey,
	}, http.StatusConflict, "Users delete API key cannot delete final admin")
}

func writeStandaloneDeletionSubject(t *testing.T, target string) {
	t.Helper()
	if path := os.Getenv("GOAUTHY_E2E_USER_DELETE_SUBJECT_FILE"); path != "" {
		if err := os.WriteFile(filepath.Clean(path), []byte(target), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// The admin state endpoint belongs only to the disposable local SCIM fixture;
// it is used here to synchronize on observable remote state, never to mutate
// the GoAuthy database or stand in for the production deletion route.
func waitForStandaloneSCIMUser(t *testing.T, subject string) {
	t.Helper()
	adminURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SCIM_ADMIN_URL"), "/")
	if adminURL == "" {
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if standaloneSCIMStateHasUser(t, client, adminURL, subject) {
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-timer.C:
			t.Fatalf("timed out waiting for SCIM fixture user externalId=%q", subject)
		case <-ticker.C:
		}
	}
}

func waitForStandaloneSCIMDeletion(t *testing.T, subject string) {
	t.Helper()
	adminURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SCIM_ADMIN_URL"), "/")
	if adminURL == "" {
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		present, deleted := standaloneSCIMState(t, client, adminURL, subject)
		if !present && deleted {
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-timer.C:
			t.Fatalf("timed out waiting for SCIM DELETE externalId=%q", subject)
		case <-ticker.C:
		}
	}
}

func standaloneSCIMStateHasUser(t *testing.T, client *http.Client, adminURL, subject string) bool {
	present, _ := standaloneSCIMState(t, client, adminURL, subject)
	return present
}

func standaloneSCIMState(t *testing.T, client *http.Client, adminURL, subject string) (bool, bool) {
	t.Helper()
	response, err := client.Get(adminURL + "/admin/state")
	if err != nil {
		return false, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, false
	}
	var state struct {
		Users []struct {
			ExternalID string `json:"externalId"`
		} `json:"users"`
		Calls []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"calls"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&state); err != nil {
		return false, false
	}
	present := false
	for _, user := range state.Users {
		if user.ExternalID == subject {
			present = true
			break
		}
	}
	deleted := false
	for _, call := range state.Calls {
		if call.Method == http.MethodDelete && strings.HasPrefix(call.Path, "/scim/v2/Users/") {
			deleted = true
			break
		}
	}
	return present, deleted
}

// TestStandaloneUserDeletionAfterRestart proves that the deleted credential is
// not revived by a fresh standalone process, while the protected admin still
// authenticates from the same persistent database.
func TestStandaloneUserDeletionAfterRestart(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_USER_DELETE_AFTER_RESTART") != "1" {
		t.Skip("set GOAUTHY_E2E_USER_DELETE_AFTER_RESTART=1 to run restart deletion E2E")
	}
	primary, secondary, adminUsername, adminPassword, _ := browserE2EConfig(t)
	path := os.Getenv("GOAUTHY_E2E_USER_DELETE_SUBJECT_FILE")
	if path != "" {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		waitForStandaloneSCIMDeletion(t, string(bytes.TrimSpace(data)))
	}
	assertPasswordLogin(t, primary, secondary, standaloneAPIKeyDeleteEmail, "api-key-deleted-user-after-restart", standaloneAPIKeyDeletePass, http.StatusUnauthorized)
	assertPasswordLogin(t, primary, secondary, adminUsername, "final-admin-after-restart", adminPassword, http.StatusFound)
}

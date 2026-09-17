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

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

const (
	scimDeleteEmail    = "scim-delete@goauthy.e2e"
	scimDeletePassword = "SCIM-Delete-Password-1A"
)

// TestSCIMUserDeletionAcrossPods is intentionally split so an external SCIM
// provider can observe the local user before and after the public admin delete.
func TestSCIMUserDeletionAcrossPods(t *testing.T) {
	phase := os.Getenv("GOAUTHY_E2E_SCIM_PHASE")
	if phase == "" {
		t.Skip("set GOAUTHY_E2E_SCIM_PHASE=create|delete|verify-deleted to run SCIM deletion E2E")
	}
	primary, secondary, adminUsername, adminPassword, stateFile := scimE2EConfig(t)
	switch phase {
	case "create":
		sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
		if sinkURL == "" {
			t.Skip("set GOAUTHY_E2E_SMTP_SINK_URL for SCIM creation E2E")
		}
		mailbox := &http.Client{Timeout: 5 * time.Second}
		clearSMTPMailbox(t, mailbox, sinkURL)
		subject := registerUserDeleteUser(t, mailbox, primary, secondary, sinkURL, scimDeleteEmail, scimDeletePassword, "scim_delete")
		assertPasswordLogin(t, primary, secondary, scimDeleteEmail, "scim-create", scimDeletePassword, http.StatusFound)
		writeSCIMSubject(t, stateFile, subject)
		groupStateFile := os.Getenv("GOAUTHY_E2E_SCIM_GROUP_STATE_FILE")
		if groupStateFile == "" {
			t.Skip("set GOAUTHY_E2E_SCIM_GROUP_STATE_FILE for SCIM group E2E")
		}
		admin := newBrowserClient(t)
		_, adminCookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-group-admin", "scim-group-admin-nonce"), primary, secondary, adminUsername, adminPassword, "scim-group-admin")
		csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		group := rbacCreate(t, admin, primary, "groups", "scim-e2e-group", nil, csrf)
		patchSCIMGroupMembership(t, admin, primary, subject, group.Name, csrf)
		patchSCIMGroupMembership(t, admin, secondary, "bootstrap-admin", group.Name, csrf)
		rbacAssertListed(t, admin, primary, "groups", group)
		writeSCIMGroupState(t, groupStateFile, group.ID)
	case "delete":
		subject := readSCIMSubject(t, stateFile)
		target := newBrowserClient(t)
		_, targetCookie := loginForAuthorizationURL(t, target, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-delete-target", "scim-delete-target-nonce"), primary, secondary, scimDeleteEmail, scimDeletePassword, "scim-delete-target")

		admin := newBrowserClient(t)
		_, adminCookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-delete-admin", "scim-delete-admin-nonce"), primary, secondary, adminUsername, adminPassword, "scim-delete-admin")
		csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		deleteSCIMUser(t, admin, primary, subject, csrf, http.StatusNoContent)
		deleteSCIMUser(t, admin, secondary, subject, csrf, http.StatusNotFound)
		assertUserDeleteSessionRejected(t, primary, targetCookie, "scim-delete-old-session-primary")
		assertUserDeleteSessionRejected(t, secondary, targetCookie, "scim-delete-old-session-secondary")
	case "verify-deleted":
		_ = readSCIMSubject(t, stateFile)
		assertPasswordLogin(t, primary, secondary, scimDeleteEmail, "scim-deleted-primary", scimDeletePassword, http.StatusUnauthorized)
		assertPasswordLogin(t, secondary, primary, scimDeleteEmail, "scim-deleted-secondary", scimDeletePassword, http.StatusUnauthorized)
	default:
		t.Fatalf("GOAUTHY_E2E_SCIM_PHASE=%q, want create, delete, or verify-deleted", phase)
	}
}

func scimE2EConfig(t *testing.T) (primary, secondary, username, password, stateFile string) {
	t.Helper()
	primary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary = strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	if secondary == "" {
		secondary = primary
	}
	username = os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	password = os.Getenv("GOAUTHY_E2E_BROWSER_PASSWORD")
	stateFile = os.Getenv("GOAUTHY_E2E_SCIM_STATE_FILE")
	if primary == "" || username == "" || password == "" || stateFile == "" {
		t.Skip("set GOAUTHY_E2E_URL, browser username/password, and GOAUTHY_E2E_SCIM_STATE_FILE to run SCIM deletion E2E")
	}
	return primary, secondary, username, password, stateFile
}

func deleteSCIMUser(t *testing.T, client *http.Client, base, subject, csrf string, want int) {
	t.Helper()
	response := do(t, client, http.MethodDelete, base+"/auth/v1/users/"+url.PathEscape(subject), nil, map[string]string{
		"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf,
	})
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("SCIM admin delete via %s status=%d, want %d", base, response.StatusCode, want)
	}
}

func writeSCIMSubject(t *testing.T, stateFile, subject string) {
	t.Helper()
	if subject == "" {
		t.Fatal("SCIM test user has no subject")
	}
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, []byte(subject+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateFile, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeSCIMGroupState(t *testing.T, stateFile, groupID string) {
	t.Helper()
	if groupID == "" {
		t.Fatal("SCIM test group has no id")
	}
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, []byte(groupID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateFile, 0o600); err != nil {
		t.Fatal(err)
	}
}

func patchSCIMGroupMembership(t *testing.T, client *http.Client, base, subject, group, csrf string) {
	t.Helper()
	body := []byte(`{"put":[{"key":"groups","value":["` + group + `"]}],"del":[]}`)
	response := do(t, client, http.MethodPatch, base+"/auth/v1/users/"+url.PathEscape(subject), bytes.NewReader(body), map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf,
	})
	defer response.Body.Close()
	var got rbacMembership
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&got)
	if response.StatusCode != http.StatusOK || err != nil || len(got.Groups) != 1 || got.Groups[0] != group {
		t.Fatalf("SCIM group membership patch via %s status=%d", base, response.StatusCode)
	}
}

func readSCIMSubject(t *testing.T, stateFile string) string {
	t.Helper()
	info, err := os.Stat(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("SCIM state file mode=%#o, want regular 0600", info.Mode())
	}
	value, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	subject := strings.TrimSpace(string(value))
	if subject == "" || strings.ContainsAny(subject, "\r\n") {
		t.Fatal("SCIM state file must contain exactly one subject")
	}
	return subject
}

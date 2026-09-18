package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	stdmail "net/mail"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/rbac"
)

const updateUserEmail = "admin-updated@goauthy.e2e"
const updateUserPassword = "Admin-Update-Password-1A"

func TestAdminUserUpdateAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_USER_CREATE") != "1" {
		t.Skip("requires administrator lifecycle fixture")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "admin-update")
	csrf, _ := browsersession.DeriveCSRFToken(cookie.Value)
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	sink := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if sink == "" {
		t.Fatal("SMTP sink required")
	}
	oldEmail := "admin-update-before@goauthy.e2e"
	created := do(t, client, http.MethodPost, primary+"/auth/v1/users", strings.NewReader(`{"email":"admin-update-before@goauthy.e2e","language":"en","roles":[],"preferred_username":"updated-user"}`), headers)
	var user rbac.UserResponse
	err := json.NewDecoder(created.Body).Decode(&user)
	created.Body.Close()
	if created.StatusCode != 200 || err != nil || user.ID == "" {
		t.Fatalf("create status=%d", created.StatusCode)
	}
	body := map[string]any{"email": oldEmail, "language": "ko", "given_name": "Updated", "roles": []string{}, "enabled": true, "email_verified": true, "password": updateUserPassword, "user_expires": int64(4102444800), "user_values": map[string]any{"tz": "Asia/Seoul", "zip": "12345"}}
	put := func(base string) rbac.UserResponse {
		t.Helper()
		payload, _ := json.Marshal(body)
		r := do(t, client, http.MethodPut, base+"/auth/v1/users/"+user.ID, bytes.NewReader(payload), headers)
		defer r.Body.Close()
		var updated rbac.UserResponse
		if r.StatusCode != 200 || json.NewDecoder(r.Body).Decode(&updated) != nil {
			t.Fatalf("update node=%s status=%d", base, r.StatusCode)
		}
		return updated
	}
	missingGivenName := make(map[string]any)
	for key, value := range body {
		missingGivenName[key] = value
	}
	delete(missingGivenName, "given_name")
	mailCountBefore := smtpMessageCount(t, client, sink)
	invalidPayload, _ := json.Marshal(missingGivenName)
	invalidPut := do(t, client, http.MethodPut, secondary+"/auth/v1/users/"+user.ID, bytes.NewReader(invalidPayload), headers)
	invalidPut.Body.Close()
	if invalidPut.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing given_name status=%d", invalidPut.StatusCode)
	}
	if count := smtpMessageCount(t, client, sink); count != mailCountBefore {
		t.Fatalf("rejected missing given_name changed mail count: before=%d after=%d", mailCountBefore, count)
	}
	updated := put(secondary)
	if updated.AccountType != "password" || updated.UserExpires == nil || *updated.UserExpires != 4102444800 {
		t.Fatal("administrator first-password assignment failed")
	}
	delete(body, "password")
	targetClient := newBrowserClient(t)
	_, _ = loginForCode(t, targetClient, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), oldEmail, updateUserPassword, "update-before-email")
	clearSMTPMailbox(t, client, sink)
	body["email"] = updateUserEmail
	updated = put(primary)
	if updated.Email != updateUserEmail || updated.UserValues.PreferredUsername == nil || *updated.UserValues.PreferredUsername != "updated-user" {
		t.Fatal("email update lost preferred username")
	}
	// SMTP acknowledgement precedes the PUT response; read observed state once,
	// with no sleeps or timing-based assumption about when mail should arrive.
	r := do(t, client, http.MethodGet, sink+"/messages", nil, nil)
	var mailbox struct {
		Messages []smtpSinkMessage `json:"messages"`
	}
	err = json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&mailbox)
	r.Body.Close()
	if r.StatusCode != 200 || err != nil || len(mailbox.Messages) != 2 {
		t.Fatalf("email change notices=%d status=%d", len(mailbox.Messages), r.StatusCode)
	}
	seen := map[string]bool{}
	for _, item := range mailbox.Messages {
		if len(item.To) != 1 || (item.To[0] != oldEmail && item.To[0] != updateUserEmail) || seen[item.To[0]] {
			t.Fatal("wrong change notice recipient")
		}
		seen[item.To[0]] = true
		mail, err := stdmail.ReadMessage(strings.NewReader(item.Data))
		if err != nil {
			t.Fatal(err)
		}
		subject, err := new(mime.WordDecoder).DecodeHeader(mail.Header.Get("Subject"))
		if err != nil || subject != "이메일 변경이 승인되었습니다:" {
			t.Fatal("notice language mismatch")
		}
		var parts resetMail
		if err := collectResetMailParts(mail.Header, mail.Body, &parts, 0); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(parts.plain, updateUserEmail) || !strings.Contains(parts.plain, "이 작업은 관리자가 수행했습니다.") || !strings.Contains(parts.html, updateUserEmail) || strings.Contains(parts.html, "href=") {
			t.Fatal("incorrect change notification")
		}
	}
	for _, base := range nodes {
		r := do(t, targetClient, http.MethodGet, base+"/auth/v1/users/"+user.ID, nil, nil)
		r.Body.Close()
		if r.StatusCode != 401 {
			t.Fatalf("old session accepted node=%s status=%d", base, r.StatusCode)
		}
		assertPasswordLogin(t, base, base, updateUserEmail, "updated-email", updateUserPassword, http.StatusFound)
	}
	body["enabled"] = false
	put(secondary)
	for _, base := range nodes {
		assertPasswordLogin(t, base, base, updateUserEmail, "update-disabled", updateUserPassword, http.StatusUnauthorized)
	}
	body["enabled"] = true
	delete(body, "user_expires")
	updated = put(primary)
	if !updated.Enabled || updated.UserExpires != nil {
		t.Fatal("reactivation/expiry clearing failed")
	}
	for _, base := range nodes {
		assertPasswordLogin(t, base, base, updateUserEmail, "update-reactivated", updateUserPassword, http.StatusFound)
	}
	assertAdminUserUpdateState(t, client, nodes, user.ID)
}

func assertAdminUserUpdateState(t *testing.T, client *http.Client, nodes []string, subject string) {
	t.Helper()
	var previous map[eventlog.Type]eventlog.Event
	for _, base := range nodes {
		r := do(t, client, http.MethodGet, base+"/auth/v1/users/"+subject, nil, nil)
		var user rbac.UserResponse
		err := json.NewDecoder(r.Body).Decode(&user)
		r.Body.Close()
		if r.StatusCode != 200 || err != nil || user.Email != updateUserEmail || user.Language != "ko" || !user.Enabled || !user.EmailVerified || user.UserExpires != nil || user.GivenName == nil || *user.GivenName != "Updated" || user.UserValues.Timezone == nil || *user.UserValues.Timezone != "Asia/Seoul" || user.UserValues.ZIP == nil || *user.UserValues.ZIP != "12345" {
			t.Fatalf("persisted update node=%s status=%d", base, r.StatusCode)
		}
		r = do(t, client, http.MethodPost, base+"/auth/v1/events", strings.NewReader(`{"from":1719784800,"until":4102444800,"level":"notice"}`), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
		var events []eventlog.Event
		err = json.NewDecoder(r.Body).Decode(&events)
		r.Body.Close()
		if r.StatusCode != 200 || err != nil {
			t.Fatal("update event read failed")
		}
		got := map[eventlog.Type]eventlog.Event{}
		for _, e := range events {
			if e.Text == nil || (*e.Text != "Change by admin: admin-update-before@goauthy.e2e -> "+updateUserEmail && *e.Text != "Reset done by admin for user admin-update-before@goauthy.e2e") {
				continue
			}
			if e.Type != eventlog.UserEmailChange && e.Type != eventlog.UserPasswordReset {
				t.Fatal("incorrect update event type")
			}
			if _, exists := got[e.Type]; exists {
				t.Fatal("duplicate update event")
			}
			if e.Level != eventlog.Notice || e.IP != nil || e.Data != nil || e.ID == "" {
				t.Fatal("incorrect update event payload")
			}
			got[e.Type] = e
		}
		if len(got) != 2 || previous != nil && !reflect.DeepEqual(previous, got) {
			t.Fatal("cross-node update events differ")
		}
		previous = got
	}
}

func TestAdminUserUpdatePersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_EVENTS_PERSISTENCE") != "1" {
		t.Skip("requires lifecycle restart fixture")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, _ = loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "update-persisted")
	r := do(t, client, http.MethodGet, primary+"/auth/v1/users", nil, nil)
	var users []rbac.UserResponseSimple
	err := json.NewDecoder(r.Body).Decode(&users)
	r.Body.Close()
	if r.StatusCode != 200 || err != nil {
		t.Fatal("user list after restart failed")
	}
	subject := ""
	for _, u := range users {
		if u.Email == updateUserEmail {
			subject = u.ID
		}
	}
	if subject == "" {
		t.Fatal("updated user missing after restart")
	}
	assertAdminUserUpdateState(t, client, adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL")), subject)
	assertPasswordLogin(t, primary, secondary, updateUserEmail, "updated-after-restart", updateUserPassword, http.StatusFound)
}

// Standalone aliases three configured URLs. Exercise each actual endpoint
// once: repeated negative logins share the durable IP failure budget.
func adminUpdateNodes(bases ...string) []string {
	nodes := []string{}
	for _, base := range bases {
		base = strings.TrimRight(base, "/")
		if base != "" && !slices.Contains(nodes, base) {
			nodes = append(nodes, base)
		}
	}
	return nodes
}

func TestAdminUserUpdateNodeSelection(t *testing.T) {
	for _, tc := range []struct{ configured, want []string }{
		{[]string{"http://one", "http://one/", "http://one"}, []string{"http://one"}},
		{[]string{"http://a", "http://b", "http://c"}, []string{"http://a", "http://b", "http://c"}},
		{[]string{"http://a", "", "http://a"}, []string{"http://a"}},
	} {
		if got := adminUpdateNodes(tc.configured...); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("nodes=%v want=%v", got, tc.want)
		}
	}
}

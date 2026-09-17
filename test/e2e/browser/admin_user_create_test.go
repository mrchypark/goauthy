package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

type createdUserDetail struct {
	ID, Email, Language string
	AccountType         string         `json:"account_type"`
	EmailVerified       bool           `json:"email_verified"`
	CreatedAt           int64          `json:"created_at"`
	LastLogin           *int64         `json:"last_login"`
	Roles               []string       `json:"roles"`
	UserExpires         *int64         `json:"user_expires"`
	UserValues          map[string]any `json:"user_values"`
}

func TestAdminUserCreateLifecycle(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_USER_CREATE") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_USER_CREATE=1 to run admin user-create E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		tertiary = secondary
	}
	sink := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if sink == "" {
		t.Fatal("GOAUTHY_E2E_SMTP_SINK_URL is required")
	}
	mailbox := newBrowserClient(t)
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, sessionCookie := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "admin-create", "admin-create-nonce"), primary, secondary, username, password, "admin-create")
	csrf, _ := browsersession.DeriveCSRFToken(sessionCookie.Value)
	email := "admin-created@goauthy.e2e"
	expires := int64(4102444800)
	body, _ := json.Marshal(map[string]any{"email": email, "language": "ko", "roles": []string{"rauthy_admin"}, "given_name": "Created", "family_name": "Admin", "preferred_username": "created-admin", "user_expires": expires, "tz": "Asia/Seoul"})
	var subject string
	for _, base := range []string{primary} {
		r := do(t, client, http.MethodPost, base+"/auth/v1/users", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("create status=%d body=%s", r.StatusCode, b)
		}
		var u createdUserDetail
		if json.Unmarshal(b, &u) != nil || u.ID == "" || u.Email != email || u.Language != "ko" || u.AccountType != "new" || u.EmailVerified || !slices.Contains(u.Roles, "rauthy_admin") || u.UserExpires == nil || *u.UserExpires != expires || u.UserValues["tz"] != "Asia/Seoul" {
			t.Fatalf("create response=%s", b)
		}
		subject = u.ID
	}
	assertCreateOnlyAPIKeyUser(t, client, csrf, primary, secondary, tertiary)
	assertDelegatedUserCreation(t, client, csrf, primary, secondary, tertiary)
	baselineEvents := assertAdminCreateEvents(t, client, []string{primary, secondary, tertiary}, email)
	for _, base := range []string{primary, secondary, tertiary} {
		r := do(t, client, http.MethodPost, base+"/auth/v1/users", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusNotAcceptable {
			t.Fatalf("duplicate create status=%d body=%s", r.StatusCode, b)
		}
	}
	assertAdminCreateEventsUnchanged(t, client, []string{primary, secondary, tertiary}, email, baselineEvents)
	for _, base := range []string{primary, secondary, tertiary} {
		r := do(t, client, http.MethodGet, base+"/auth/v1/users/"+url.PathEscape(subject), nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
		var u createdUserDetail
		err := json.NewDecoder(r.Body).Decode(&u)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || err != nil || u.ID != subject || u.Email != email || u.Language != "ko" || u.AccountType != "new" || u.EmailVerified || u.UserExpires == nil || *u.UserExpires != expires || u.UserValues["tz"] != "Asia/Seoul" {
			t.Fatalf("detail node=%s status=%d err=%v", base, r.StatusCode, err)
		}
	}
	mail := waitForResetMail(t, mailbox, sink, email)
	parsed, err := url.Parse(mail.resetURL)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) != 6 {
		t.Fatalf("reset path=%q", parsed.Path)
	}
	activation := newBrowserClient(t)
	r := do(t, activation, http.MethodGet, primary+parsed.EscapedPath(), nil, nil)
	var challenge struct {
		CSRFToken string `json:"csrf_token"`
	}
	json.NewDecoder(r.Body).Decode(&challenge)
	cookies := r.Cookies()
	r.Body.Close()
	if r.StatusCode != http.StatusOK || challenge.CSRFToken == "" {
		t.Fatal("activation start failed")
	}
	secondaryURL, _ := url.Parse(secondary)
	activation.Jar.SetCookies(secondaryURL, cookies)
	put, _ := json.Marshal(map[string]string{"magic_link_id": parts[5], "password": "Admin-Created-Password-1A"})
	r = do(t, activation, http.MethodPut, secondary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(put), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": challenge.CSRFToken})
	r.Body.Close()
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("activation status=%d", r.StatusCode)
	}
	tertiaryURL, err := url.Parse(tertiary)
	if err != nil {
		t.Fatal(err)
	}
	activation.Jar.SetCookies(tertiaryURL, cookies)
	r = do(t, activation, http.MethodPut, tertiary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(put), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": challenge.CSRFToken})
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("activation replay status=%d", r.StatusCode)
	}
	assertPasswordLogin(t, primary, secondary, email, "admin-create-login", "Admin-Created-Password-1A", http.StatusFound)
	for _, base := range []string{primary, secondary, tertiary} {
		r = do(t, client, http.MethodGet, base+"/auth/v1/users/"+url.PathEscape(subject), nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
		var u createdUserDetail
		err := json.NewDecoder(r.Body).Decode(&u)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || err != nil || u.AccountType != "password" || !u.EmailVerified || u.CreatedAt <= 0 || u.LastLogin == nil || *u.LastLogin <= 0 || u.UserExpires == nil || *u.UserExpires != expires || u.UserValues["tz"] != "Asia/Seoul" {
			t.Fatalf("activated detail node=%s status=%d err=%v", base, r.StatusCode, err)
		}
	}
}

func assertAdminCreateEvents(t *testing.T, session *http.Client, bases []string, email string) map[eventlog.Type]string {
	t.Helper()
	ids := make(map[eventlog.Type]string, 2)
	for _, base := range bases {
		body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info"}`))
		r := do(t, session, http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
		var events []eventlog.Event
		err := json.NewDecoder(r.Body).Decode(&events)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("events node=%s status=%d err=%v", base, r.StatusCode, err)
		}
		counts := map[eventlog.Type]int{}
		for _, event := range events {
			if event.Text == nil || *event.Text != email || (event.Type != eventlog.NewUserRegistered && event.Type != eventlog.NewRauthyAdmin) {
				continue
			}
			counts[event.Type]++
			wantLevel := eventlog.Info
			if event.Type == eventlog.NewRauthyAdmin {
				wantLevel = eventlog.Notice
			}
			validIP := true
			if event.IP != nil {
				_, err := netip.ParseAddr(*event.IP)
				validIP = err == nil
			}
			if event.Timestamp <= 0 || event.Data != nil || event.Level != wantLevel || event.ID == "" || !validIP {
				t.Fatalf("invalid lifecycle event node=%s event=%+v", base, event)
			}
			if prior, ok := ids[event.Type]; ok && prior != event.ID {
				t.Fatalf("event id differs node=%s type=%s", base, event.Type)
			}
			ids[event.Type] = event.ID
		}
		if counts[eventlog.NewUserRegistered] != 1 || counts[eventlog.NewRauthyAdmin] != 1 {
			t.Fatalf("lifecycle event counts node=%s: %+v", base, counts)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("missing lifecycle event ids: %+v", ids)
	}
	return ids
}

func assertAdminCreateEventsUnchanged(t *testing.T, session *http.Client, bases []string, email string, baseline map[eventlog.Type]string) {
	t.Helper()
	for _, base := range bases {
		body := bytes.NewReader([]byte(`{"from":1719784800,"until":4102444800,"level":"info"}`))
		r := do(t, session, http.MethodPost, base+"/auth/v1/events", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
		var events []eventlog.Event
		err := json.NewDecoder(r.Body).Decode(&events)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("events after duplicate node=%s status=%d err=%v", base, r.StatusCode, err)
		}
		counts := map[eventlog.Type]int{}
		for _, event := range events {
			if event.Text != nil && *event.Text == email && (event.Type == eventlog.NewUserRegistered || event.Type == eventlog.NewRauthyAdmin) {
				counts[event.Type]++
				if baseline[event.Type] != event.ID {
					t.Fatalf("event changed after duplicate node=%s type=%s", base, event.Type)
				}
			}
		}
		if counts[eventlog.NewUserRegistered] != 1 || counts[eventlog.NewRauthyAdmin] != 1 {
			t.Fatalf("duplicate appended lifecycle event node=%s counts=%+v", base, counts)
		}
	}
}

func assertCreateOnlyAPIKeyUser(t *testing.T, admin *http.Client, csrf, primary, secondary, tertiary string) {
	t.Helper()
	name := "create-user-" + randomManagedUIID(t)
	secret := createAdminAPIKey(t, admin, primary, csrf, name, []apiKeyAccess{{Group: "Users", AccessRights: []string{"create"}}})
	revoked := false
	t.Cleanup(func() {
		if !revoked {
			apiKeyStatus(t, admin, http.MethodDelete, primary+"/auth/v1/api_keys/"+url.PathEscape(name), nil, rbacMutationHeaders(csrf), http.StatusOK, "create key cleanup")
		}
	})
	client := newBrowserClient(t)
	headers := map[string]string{"Authorization": "API-Key " + secret, "Content-Type": "application/json"}
	email := name + "@goauthy.e2e"
	body := map[string]any{"email": email, "language": "fr", "roles": []string{}}
	response := do(t, client, http.MethodPost, secondary+"/auth/v1/users", apiKeyJSON(t, body), headers)
	var created createdUserDetail
	err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&created)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || created.ID == "" || created.Email != email {
		t.Fatalf("create-only key status=%d", response.StatusCode)
	}
	t.Cleanup(func() {
		apiKeyStatus(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(created.ID), nil, rbacMutationHeaders(csrf), http.StatusNoContent, "created user cleanup")
	})
	for _, base := range []string{primary, secondary, tertiary} {
		apiKeyStatus(t, client, http.MethodGet, base+"/auth/v1/users/"+url.PathEscape(created.ID), nil, headers, http.StatusForbidden, "create key cannot read")
		response := do(t, admin, http.MethodGet, base+"/auth/v1/users/"+url.PathEscape(created.ID), nil, nil)
		var detail createdUserDetail
		err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&detail)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil || detail.ID != created.ID || detail.Language != "fr" {
			t.Fatal("API-key creation missing across nodes")
		}
	}
	apiKeyStatus(t, admin, http.MethodDelete, tertiary+"/auth/v1/api_keys/"+url.PathEscape(name), nil, rbacMutationHeaders(csrf), http.StatusOK, "revoke create key")
	revoked = true
	body["email"] = "revoked-" + email
	for _, base := range []string{primary, secondary, tertiary} {
		apiKeyStatus(t, client, http.MethodPost, base+"/auth/v1/users", apiKeyJSON(t, body), headers, http.StatusUnauthorized, "revoked create key")
	}
}

func assertDelegatedUserCreation(t *testing.T, admin *http.Client, csrf, primary, secondary, tertiary string) {
	t.Helper()
	prefix := "create-delegated-" + randomManagedUIID(t)
	adminHeaders := rbacMutationHeaders(csrf)
	var users []string
	var entities []struct{ kind, id string }
	t.Cleanup(func() {
		for _, id := range users {
			apiKeyStatus(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(id), nil, adminHeaders, http.StatusNoContent, "delegated user cleanup")
		}
		for _, e := range entities {
			apiKeyStatus(t, admin, http.MethodDelete, primary+"/auth/v1/"+e.kind+"/"+url.PathEscape(e.id), nil, adminHeaders, http.StatusOK, "delegated entity cleanup")
		}
	})
	for _, entry := range []struct{ kind, name string }{{"roles", "rauthy_admin:" + prefix + "/*"}, {"roles", "rauthy_admin:" + prefix + "-exact"}, {"groups", prefix + "/team"}, {"groups", prefix + "-exact"}, {"groups", prefix + "-outside"}} {
		e := rbacCreate(t, admin, primary, entry.kind, entry.name, nil, csrf)
		entities = append(entities, struct{ kind, id string }{entry.kind, e.ID})
	}
	create := func(client *http.Client, base string, headers map[string]string, email string, roles, groups []string, want int) string {
		t.Helper()
		response := do(t, client, http.MethodPost, base+"/auth/v1/users", apiKeyJSON(t, map[string]any{"email": email, "language": "en", "roles": roles, "groups": groups}), headers)
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("delegated create status=%d want=%d", response.StatusCode, want)
		}
		if want != http.StatusOK {
			return ""
		}
		var detail createdUserDetail
		if json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&detail) != nil || detail.ID == "" {
			t.Fatal("delegated creation returned no subject")
		}
		users = append(users, detail.ID)
		return detail.ID
	}
	email := prefix + "@goauthy.e2e"
	delegateID := create(admin, primary, adminHeaders, email, []string{}, []string{}, http.StatusOK)
	roles := []string{"rauthy_admin:" + prefix + "/*", "rauthy_admin:" + prefix + "-exact"}
	apiKeyStatus(t, admin, http.MethodPut, primary+"/auth/v1/users/"+delegateID, apiKeyJSON(t, map[string]any{"email": email, "given_name": "Delegated", "roles": roles, "groups": []string{}, "enabled": true, "email_verified": true, "password": updateUserPassword}), adminHeaders, http.StatusOK, "delegate initialization")
	delegate, delegateCSRF := rbacAuthenticatedClient(t, primary, secondary, email, updateUserPassword)
	headers := rbacMutationHeaders(delegateCSRF)
	for i, base := range []string{primary, secondary, tertiary} {
		suffix := prefix + "-" + strconv.Itoa(i) + "@goauthy.e2e"
		create(delegate, base, headers, "allowed-"+suffix, []string{}, []string{prefix + "/team", prefix + "-exact"}, http.StatusOK)
		create(delegate, base, headers, "outside-"+suffix, []string{}, []string{prefix + "/team", prefix + "-outside"}, http.StatusForbidden)
		create(delegate, base, headers, "role-"+suffix, []string{"rauthy_admin"}, []string{prefix + "/team"}, http.StatusForbidden)
		create(delegate, base, headers, "empty-"+suffix, []string{}, []string{}, http.StatusForbidden)
	}
	// Removing wildcard authority must take effect for the existing session.
	apiKeyStatus(t, admin, http.MethodPut, primary+"/auth/v1/users/"+delegateID, apiKeyJSON(t, map[string]any{"email": email, "given_name": "Delegated", "roles": []string{roles[1]}, "groups": []string{}, "enabled": true, "email_verified": true}), adminHeaders, http.StatusOK, "remove wildcard creation authority")
	create(delegate, tertiary, headers, "exact-"+email, []string{}, []string{prefix + "-exact"}, http.StatusOK)
	create(delegate, secondary, headers, "removed-"+email, []string{}, []string{prefix + "/team"}, http.StatusForbidden)
}

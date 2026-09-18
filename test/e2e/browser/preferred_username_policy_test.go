package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestPreferredUsernamePolicyAcrossPods(t *testing.T) {
	mode := os.Getenv("GOAUTHY_E2E_PREFERRED_USERNAME_POLICY")
	if mode == "" {
		t.Skip("set GOAUTHY_E2E_PREFERRED_USERNAME_POLICY to default or custom")
	}
	if mode != "default" && mode != "custom" {
		t.Fatalf("invalid preferred username policy mode")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	for _, base := range nodes {
		assertUserValuesConfig(t, newBrowserClient(t), base, mode, nil, 200)
		assertUserValuesConfig(t, newBrowserClient(t), base, mode, map[string]string{"Authorization": "API-Key invalid", "Sec-Fetch-Site": "cross-site"}, 200)
	}
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "preferred-policy-"+mode)
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	sink := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if sink == "" {
		t.Fatal("SMTP sink is required")
	}
	patternValue, reserved := "alice_34", "root"
	if mode == "custom" {
		patternValue, reserved = "Team_34", "Team_12"
	}
	challenge := passwordResetPoWChallenge(t, client, primary)
	proof := solvePasswordResetPoW(t, challenge, 10)
	publicEmail := "policy-public-username-" + mode + "@goauthy.e2e"
	publicPayload := func(email, preferred string) []byte {
		body, _ := json.Marshal(map[string]any{"email": email, "preferred_username": preferred, "given_name": "Policy", "family_name": "User", "pow": proof, "redirect_uri": defaultRedirectURI})
		return body
	}
	baseline := smtpMessageCount(t, client, sink)
	for _, bad := range []string{"!bad", ""} {
		payload := publicPayload(publicEmail, bad)
		for _, base := range nodes {
			response := do(t, client, http.MethodPost, base+"/auth/v1/users/register", bytes.NewReader(payload), map[string]string{"Content-Type": "application/json"})
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("public invalid preferred=%q node=%s status=%d", bad, base, response.StatusCode)
			}
		}
	}
	for _, base := range nodes {
		response := do(t, client, http.MethodPost, base+"/auth/v1/users/register", bytes.NewReader(publicPayload(publicEmail, reserved)), map[string]string{"Content-Type": "application/json"})
		response.Body.Close()
		if response.StatusCode != http.StatusNotAcceptable {
			t.Fatalf("public reserved=%q mode=%s node=%s status=%d want=%d", reserved, mode, base, response.StatusCode, http.StatusNotAcceptable)
		}
	}
	if mode == "custom" {
		for _, field := range []string{"", `,"preferred_username":null`} {
			payload := `{"email":"` + publicEmail + `","given_name":"Policy","pow":"` + proof + `"` + field + `}`
			for _, base := range nodes {
				response := do(t, client, http.MethodPost, base+"/auth/v1/users/register", strings.NewReader(payload), map[string]string{"Content-Type": "application/json"})
				response.Body.Close()
				if response.StatusCode != http.StatusBadRequest {
					t.Fatalf("missing required username node=%s status=%d", base, response.StatusCode)
				}
			}
		}
	}
	if smtpMessageCount(t, client, sink) != baseline {
		t.Fatal("rejected public preferred usernames changed SMTP mailbox")
	}
	valid := do(t, client, http.MethodPost, primary+"/auth/v1/users/register", bytes.NewReader(publicPayload(publicEmail, patternValue)), map[string]string{"Content-Type": "application/json"})
	valid.Body.Close()
	if valid.StatusCode != http.StatusNoContent {
		t.Fatalf("valid public preferred status=%d", valid.StatusCode)
	}

	create := func(email, preferred string) string {
		var preferredValue any = preferred
		if preferred == "" {
			preferredValue = nil
		}
		body, _ := json.Marshal(map[string]any{"email": email, "language": "en", "roles": []string{}, "preferred_username": preferredValue})
		response := do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewReader(body), adminHeaders)
		var result struct {
			ID string `json:"id"`
		}
		err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&result)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil || result.ID == "" {
			t.Fatalf("admin create preferred=%q status=%d err=%v", preferred, response.StatusCode, err)
		}
		return result.ID
	}
	adminEmail := "policy-admin-username-" + mode + "@goauthy.e2e"
	absentEmail := "policy-absent-username-" + mode + "@goauthy.e2e"
	adminID := create(adminEmail, "")
	absentID := create(absentEmail, reserved)
	if got := readPreferredUsername(t, client, primary, adminID); got != nil {
		t.Fatalf("null admin preferred username = %q", *got)
	}
	if got := readPreferredUsername(t, client, primary, absentID); got == nil || *got != reserved {
		t.Fatalf("admin reserved preferred username = %v", got)
	}

	before := smtpMessageCount(t, client, sink)
	usersBefore := preferredPolicyUsers(t, client, primary)
	for _, preferred := range []string{"!bad", ""} {
		body, _ := json.Marshal(map[string]any{"email": "invalid-preferred@goauthy.e2e", "preferred_username": preferred, "language": "en", "roles": []string{}})
		for _, base := range nodes {
			response := do(t, client, http.MethodPost, base+"/auth/v1/users", bytes.NewReader(body), adminHeaders)
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("admin invalid preferred=%q node=%s status=%d", preferred, base, response.StatusCode)
			}
		}
	}
	if smtpMessageCount(t, client, sink) != before {
		t.Fatal("rejected admin preferred usernames changed SMTP mailbox")
	}
	for _, base := range nodes {
		if !reflect.DeepEqual(preferredPolicyUsers(t, client, base), usersBefore) {
			t.Fatalf("rejected admin creation changed users on %s", base)
		}
	}
	assertPreferredProfiles(t, client, nodes, map[string]string{publicEmail: patternValue, adminEmail: "", absentEmail: reserved})
	// Assign a real password with the existing administrator lifecycle, then
	// exercise the self-service route with a non-administrator browser session.
	activation, _ := json.Marshal(map[string]any{"email": adminEmail, "given_name": "Policy", "roles": []string{}, "enabled": true, "email_verified": true, "password": updateUserPassword})
	apiKeyStatus(t, client, http.MethodPut, primary+"/auth/v1/users/"+adminID, bytes.NewReader(activation), adminHeaders, 200, "activate preferred-username member")
	member := newBrowserClient(t)
	_, memberCookie := loginForCode(t, member, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminEmail, updateUserPassword, "preferred-member")
	memberCSRF, err := browsersession.DeriveCSRFToken(memberCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	memberHeaders := rbacMutationHeaders(memberCSRF)
	first, second, raced, finalOther := "alice_45", "alice_56", "alice_78", ""
	if mode == "custom" {
		first, second, raced, finalOther = "Team_45", "Team_56", "Team_78", "Team_67"
	}
	putName := func(c *http.Client, base, id string, headers map[string]string, name any, force bool, want int) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"preferred_username": name, "force_overwrite": force})
		r := do(t, c, http.MethodPut, base+"/auth/v1/users/"+id+"/self/preferred_username", bytes.NewReader(body), headers)
		responseBody, readErr := io.ReadAll(io.LimitReader(r.Body, 4096))
		r.Body.Close()
		if r.StatusCode != want || readErr != nil || want == 200 && len(responseBody) != 0 {
			t.Fatalf("preferred mutation node=%s status=%d want=%d read=%v", base, r.StatusCode, want, readErr)
		}
	}
	mailBeforeUpdate := smtpMessageCount(t, client, sink)
	profileBefore := readPolicyProfile(t, client, primary, adminID)
	putName(member, primary, adminID, memberHeaders, first, false, 200)
	for _, base := range nodes {
		putName(member, base, adminID, memberHeaders, second, true, 403)
		putName(member, base, absentID, memberHeaders, second, false, 403)
		putName(client, base, adminID, adminHeaders, reserved, true, 406)
		putName(client, base, adminID, adminHeaders, patternValue, true, 406)
		putName(member, base, adminID, map[string]string{"Content-Type": "application/json"}, second, false, 401)
		status := 400
		if mode == "custom" {
			status = 200
		}
		putName(member, base, adminID, memberHeaders, second, false, status)
	}
	// A Users:update-only key may force, but cannot bypass value policy.
	key := createAdminAPIKey(t, client, primary, csrf, "preferred-update-"+mode, []apiKeyAccess{{Group: "Users", AccessRights: []string{"update"}}})
	keyHeaders := map[string]string{"Content-Type": "application/json", "Authorization": "API-Key " + key}
	keyClient := newBrowserClient(t)
	for _, base := range nodes {
		putName(keyClient, base, adminID, keyHeaders, first, true, 200)
		putName(keyClient, base, adminID, keyHeaders, reserved, true, 406)
		clearStatus := 200
		if mode == "custom" {
			clearStatus = 400
		}
		putName(keyClient, base, adminID, keyHeaders, nil, true, clearStatus)
		putName(keyClient, base, adminID, keyHeaders, first, true, 200)
	}
	// Competing requests may win in either order; exactly one winner and one
	// conflict is deterministic. The database, not a sleep, is the barrier.
	start := make(chan struct{})
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for i, id := range []string{adminID, absentID} {
		wg.Add(1)
		go func(base, id string) {
			defer wg.Done()
			<-start
			body, _ := json.Marshal(map[string]any{"preferred_username": raced, "force_overwrite": true})
			req, err := http.NewRequest(http.MethodPut, base+"/auth/v1/users/"+id+"/self/preferred_username", bytes.NewReader(body))
			if err != nil {
				results <- 0
				return
			}
			for name, value := range keyHeaders {
				req.Header.Set(name, value)
			}
			r, err := keyClient.Do(req)
			if err != nil {
				results <- 0
				return
			}
			r.Body.Close()
			results <- r.StatusCode
		}(nodes[i%len(nodes)], id)
	}
	close(start)
	wg.Wait()
	a, b := <-results, <-results
	if !((a == 200 && b == 406) || (a == 406 && b == 200)) {
		t.Fatalf("competing preferred writes: %d, %d", a, b)
	}
	putName(client, primary, adminID, adminHeaders, first, true, 200)
	var other any
	if finalOther != "" {
		other = finalOther
	}
	putName(client, secondary, absentID, adminHeaders, other, true, 200)
	assertPreferredProfiles(t, client, nodes, map[string]string{publicEmail: patternValue, adminEmail: first, absentEmail: finalOther})
	for _, base := range nodes {
		profileAfter := readPolicyProfile(t, client, base, adminID)
		delete(profileAfter["user_values"].(map[string]any), "preferred_username")
		delete(profileBefore["user_values"].(map[string]any), "preferred_username")
		if !reflect.DeepEqual(profileBefore, profileAfter) {
			t.Fatal("preferred mutation changed unrelated profile fields")
		}
		// The original member session must remain usable after a username edit.
		apiKeyStatus(t, member, http.MethodGet, base+"/auth/v1/users/"+adminID, nil, nil, 200, "member session survives preferred edit")
	}
	if smtpMessageCount(t, client, sink) != mailBeforeUpdate {
		t.Fatal("preferred username updates unexpectedly sent mail")
	}
	apiKeyStatus(t, client, http.MethodDelete, primary+"/auth/v1/api_keys/preferred-update-"+mode, nil, adminHeaders, 200, "revoke preferred update key")
	for _, base := range nodes {
		putName(keyClient, base, adminID, keyHeaders, second, true, 401)
	}
	// A delegated administrator may initialize only a currently managed target;
	// mutable configuration must not turn that privilege into overwrite access.
	rbacCreate(t, client, primary, "roles", "rauthy_admin:preferred/*", nil, csrf)
	rbacCreate(t, client, primary, "groups", "preferred/team", nil, csrf)
	delegatedEmail := "policy-delegated-" + mode + "@goauthy.e2e"
	managedEmail := "policy-managed-" + mode + "@goauthy.e2e"
	delegatedID, managedID := create(delegatedEmail, ""), create(managedEmail, "")
	for _, row := range []struct {
		id, email     string
		roles, groups []string
	}{{delegatedID, delegatedEmail, []string{"rauthy_admin:preferred/*"}, []string{}}, {managedID, managedEmail, []string{}, []string{"preferred/team"}}} {
		payload, _ := json.Marshal(map[string]any{"email": row.email, "given_name": "Policy", "roles": row.roles, "groups": row.groups, "enabled": true, "email_verified": true, "password": updateUserPassword})
		apiKeyStatus(t, client, http.MethodPut, primary+"/auth/v1/users/"+row.id, bytes.NewReader(payload), adminHeaders, 200, "set delegated fixture membership")
	}
	delegate, delegateCSRF := rbacAuthenticatedClient(t, primary, secondary, delegatedEmail, updateUserPassword)
	delegateHeaders := rbacMutationHeaders(delegateCSRF)
	managedName := "delegate_89"
	if mode == "custom" {
		managedName = "Team_89"
	}
	putName(delegate, secondary, managedID, delegateHeaders, managedName, false, 200)
	for _, base := range nodes {
		putName(delegate, base, managedID, delegateHeaders, second, false, 403)
		putName(delegate, base, managedID, delegateHeaders, second, true, 403)
		putName(delegate, base, adminID, delegateHeaders, second, false, 428)
	}
	removeGroup, _ := json.Marshal(map[string]any{"email": managedEmail, "given_name": "Policy", "roles": []string{}, "enabled": true, "email_verified": true})
	apiKeyStatus(t, client, http.MethodPut, primary+"/auth/v1/users/"+managedID, bytes.NewReader(removeGroup), adminHeaders, 200, "remove delegated target scope")
	for _, base := range nodes {
		putName(delegate, base, managedID, delegateHeaders, second, false, 428)
	}
	assertPreferredProfiles(t, client, nodes, map[string]string{adminEmail: first, absentEmail: finalOther, managedEmail: managedName})
}

func TestPreferredUsernamePolicyPersisted(t *testing.T) {
	mode := os.Getenv("GOAUTHY_E2E_PREFERRED_USERNAME_POLICY")
	if mode == "" {
		t.Skip("set GOAUTHY_E2E_PREFERRED_USERNAME_POLICY")
	}
	if mode != "default" && mode != "custom" {
		t.Fatal("invalid preferred username policy mode")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	for _, base := range nodes {
		assertUserValuesConfig(t, newBrowserClient(t), base, mode, nil, 200)
	}
	client := newBrowserClient(t)
	loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "preferred-policy-persisted-"+mode)
	preferred, member, other := "alice_34", "alice_45", ""
	if mode == "custom" {
		preferred, member, other = "Team_34", "Team_45", "Team_67"
	}
	assertPreferredProfiles(t, client, nodes, map[string]string{
		"policy-public-username-" + mode + "@goauthy.e2e": preferred,
		"policy-admin-username-" + mode + "@goauthy.e2e":  member,
		"policy-absent-username-" + mode + "@goauthy.e2e": other,
	})
	managed := "delegate_89"
	if mode == "custom" {
		managed = "Team_89"
	}
	assertPreferredProfiles(t, client, nodes, map[string]string{"policy-managed-" + mode + "@goauthy.e2e": managed})
}

func readPreferredUsername(t *testing.T, client *http.Client, base, id string) *string {
	t.Helper()
	profile := readPolicyProfile(t, client, base, id)
	values := profile["user_values"].(map[string]any)
	raw := values["preferred_username"]
	if raw == nil {
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		t.Fatal("preferred_username must be a string or absent/null")
	}
	return &value
}

func preferredPolicyUsers(t *testing.T, client *http.Client, base string) map[string]string {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users", nil, nil)
	var users []struct{ ID, Email string }
	err := json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&users)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("list users status=%d err=%v", response.StatusCode, err)
	}
	result := make(map[string]string, len(users))
	for _, user := range users {
		if user.ID == "" || user.Email == "" || result[user.Email] != "" {
			t.Fatal("invalid user list entry")
		}
		result[user.Email] = user.ID
	}
	return result
}

func assertPreferredProfiles(t *testing.T, client *http.Client, nodes []string, expected map[string]string) {
	t.Helper()
	var canonical map[string]string
	for _, base := range nodes {
		users := preferredPolicyUsers(t, client, base)
		if canonical == nil {
			canonical = users
		} else if !reflect.DeepEqual(users, canonical) {
			t.Fatal("user list differs across nodes")
		}
		for email, want := range expected {
			id := users[email]
			if id == "" {
				t.Fatalf("preferred profile missing node=%s email=%s", base, email)
			}
			got := readPreferredUsername(t, client, base, id)
			if want == "" && got != nil || want != "" && (got == nil || *got != want) {
				t.Fatalf("preferred profile mismatch node=%s email=%s", base, email)
			}
		}
	}
}

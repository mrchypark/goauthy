package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestUserValuesPolicyAcrossPods(t *testing.T) {
	mode := os.Getenv("GOAUTHY_E2E_USER_VALUES_MODE")
	if mode == "" {
		t.Skip("set GOAUTHY_E2E_USER_VALUES_MODE to required, optional or hidden")
	}
	if mode != "required" && mode != "optional" && mode != "hidden" {
		t.Fatalf("invalid GOAUTHY_E2E_USER_VALUES_MODE=%q", mode)
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(verifier), username, password, "user-values-policy-"+mode)
	csrf, _ := browsersession.DeriveCSRFToken(cookie.Value)
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	validValues := map[string]any{"birthdate": "2000-01-02", "phone": "+82101234", "street": "Main Street", "zip": "12345", "city": "Seoul", "country": "KR", "tz": "Asia/Seoul"}
	fields := []string{"given_name", "family_name", "birthdate", "street", "zip", "city", "country", "phone", "tz"}
	copyValues := func() map[string]any {
		out := map[string]any{}
		for k, v := range validValues {
			out[k] = v
		}
		return out
	}
	request := func(email, proof string, values map[string]any) []byte {
		body, err := json.Marshal(map[string]any{"email": email, "preferred_username": "policy_" + mode, "given_name": "Policy", "family_name": "User", "user_values": values, "pow": proof, "redirect_uri": defaultRedirectURI})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	proof := solvePasswordResetPoW(t, passwordResetPoWChallenge(t, client, primary), 10)
	publicEmail := "policy-public-" + mode + "@goauthy.e2e"
	sink := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if sink == "" {
		t.Fatal("SMTP sink is required for policy side-effect checks")
	}
	publicMailBaseline := smtpMessageCount(t, client, sink)
	if mode == "required" {
		for _, field := range fields {
			for _, variant := range []string{"omitted", "null", "empty"} {
				payload := request(publicEmail, proof, copyValues())
				var object map[string]any
				if err := json.Unmarshal(payload, &object); err != nil {
					t.Fatal(err)
				}
				omitPolicyField(object, field, variant)
				payload, _ = json.Marshal(object)
				for _, base := range nodes {
					response := do(t, client, http.MethodPost, base+"/auth/v1/users/register", bytes.NewReader(payload), map[string]string{"Content-Type": "application/json"})
					response.Body.Close()
					if response.StatusCode != http.StatusBadRequest {
						t.Fatalf("public %s %s node=%s status=%d", field, variant, base, response.StatusCode)
					}
				}
			}
		}
	}
	// Hidden/optional is not a syntax-validation bypass. This rejection also
	// reuses the same PoW below, so no timing or quota-reset helper is needed.
	var malformed map[string]any
	if json.Unmarshal(request(publicEmail, proof, copyValues()), &malformed) != nil {
		t.Fatal("invalid internal public policy fixture")
	}
	malformed["given_name"] = "\n"
	malformedPayload, _ := json.Marshal(malformed)
	for _, base := range nodes {
		response := do(t, client, http.MethodPost, base+"/auth/v1/users/register", bytes.NewReader(malformedPayload), map[string]string{"Content-Type": "application/json"})
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("malformed public name mode=%s node=%s status=%d", mode, base, response.StatusCode)
		}
	}
	if smtpMessageCount(t, client, sink) != publicMailBaseline {
		t.Fatal("rejected public policy requests changed SMTP mailbox")
	}
	publicValid := do(t, client, http.MethodPost, primary+"/auth/v1/users/register", bytes.NewReader(request(publicEmail, proof, copyValues())), map[string]string{"Content-Type": "application/json"})
	publicValid.Body.Close()
	if publicValid.StatusCode != http.StatusNoContent {
		t.Fatalf("public valid status=%d", publicValid.StatusCode)
	}
	if mode != "required" {
		sparseProof := solvePasswordResetPoW(t, passwordResetPoWChallenge(t, client, primary), 10)
		payload, _ := json.Marshal(map[string]any{"email": "policy-sparse-" + mode + "@goauthy.e2e", "preferred_username": "sparse_" + mode, "user_values": map[string]any{}, "pow": sparseProof, "redirect_uri": defaultRedirectURI})
		response := do(t, client, http.MethodPost, primary+"/auth/v1/users/register", bytes.NewReader(payload), map[string]string{"Content-Type": "application/json"})
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("sparse public status=%d", response.StatusCode)
		}
	}

	adminEmail := "policy-admin-" + mode + "@goauthy.e2e"
	created := do(t, client, http.MethodPost, primary+"/auth/v1/users", strings.NewReader(`{"email":"`+adminEmail+`","language":"en","roles":[]}`), adminHeaders)
	var user struct {
		ID string `json:"id"`
	}
	err := json.NewDecoder(io.LimitReader(created.Body, 16<<10)).Decode(&user)
	created.Body.Close()
	if created.StatusCode != http.StatusOK || err != nil || user.ID == "" {
		t.Fatalf("admin create status=%d err=%v", created.StatusCode, err)
	}
	initial := readPolicyProfile(t, client, primary, user.ID)
	if initial["account_type"] != "new" || initial["given_name"] != nil || initial["family_name"] != nil || len(initial["user_values"].(map[string]any)) != 0 {
		t.Fatal("admin creation exemption did not produce an empty pending profile")
	}
	adminBody := func(values map[string]any) []byte {
		body, _ := json.Marshal(map[string]any{"email": adminEmail, "given_name": "Policy", "family_name": "User", "roles": []string{}, "enabled": true, "email_verified": false, "user_values": values})
		return body
	}
	adminMailBeforeMalformed := smtpMessageCount(t, client, sink)
	// Use a fresh map: registration-only fields must not cause the
	// rejection intended here for malformed given_name.
	malformed = map[string]any{"email": adminEmail, "given_name": "\n", "family_name": "User", "roles": []string{}, "enabled": true, "email_verified": false, "user_values": copyValues()}
	malformedPayload, _ = json.Marshal(malformed)
	for _, base := range nodes {
		response := do(t, client, http.MethodPut, base+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(malformedPayload), adminHeaders)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest || !reflect.DeepEqual(readPolicyProfile(t, client, base, user.ID), initial) {
			t.Fatalf("malformed admin name mode=%s node=%s status=%d", mode, base, response.StatusCode)
		}
	}
	if smtpMessageCount(t, client, sink) != adminMailBeforeMalformed {
		t.Fatal("malformed admin name changed mailbox")
	}
	if mode != "required" {
		// Populate first: clearing a never-populated profile proves nothing.
		response := do(t, client, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(adminBody(copyValues())), adminHeaders)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("populate optional values status=%d", response.StatusCode)
		}
		assertUserValuesPolicyProfiles(t, client, nodes, []string{adminEmail}, validValues)
		payload, _ := json.Marshal(map[string]any{"email": adminEmail, "roles": []string{}, "enabled": true, "email_verified": false, "user_values": map[string]any{}})
		response = do(t, client, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(payload), adminHeaders)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("clear optional values status=%d", response.StatusCode)
		}
		for _, base := range nodes {
			cleared := readPolicyProfile(t, client, base, user.ID)
			if cleared["given_name"] != nil || cleared["family_name"] != nil || len(cleared["user_values"].(map[string]any)) != 0 {
				t.Fatalf("optional/hidden fields were not cleared on %s", base)
			}
		}
	}
	if mode == "required" {
		adminMailBaseline := smtpMessageCount(t, client, sink)
		for _, field := range fields {
			for _, variant := range []string{"omitted", "null", "empty"} {
				values := copyValues()
				var body map[string]any
				if json.Unmarshal(adminBody(values), &body) != nil {
					t.Fatal("invalid internal policy fixture")
				}
				omitPolicyField(body, field, variant)
				payload, _ := json.Marshal(body)
				for _, base := range nodes {
					response := do(t, client, http.MethodPut, base+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(payload), adminHeaders)
					response.Body.Close()
					if response.StatusCode != http.StatusBadRequest {
						t.Fatalf("admin %s %s node=%s status=%d", field, variant, base, response.StatusCode)
					}
				}
			}
		}
		if smtpMessageCount(t, client, sink) != adminMailBaseline {
			t.Fatal("rejected admin policy requests changed SMTP mailbox")
		}
		for _, base := range nodes {
			if !reflect.DeepEqual(readPolicyProfile(t, client, base, user.ID), initial) {
				t.Fatalf("rejected admin requests changed profile on %s", base)
			}
		}
		// Pin Rauthy's absent-parent exception without weakening the checks
		// above: only the whole null object skips nested required fields.
		response := do(t, client, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(adminBody(nil)), adminHeaders)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("null parent compatibility status=%d", response.StatusCode)
		}
	}
	for _, base := range nodes {
		response := do(t, client, http.MethodPut, base+"/auth/v1/users/"+url.PathEscape(user.ID), bytes.NewReader(adminBody(copyValues())), adminHeaders)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("admin valid node=%s status=%d", base, response.StatusCode)
		}
	}
	assertUserValuesPolicyProfiles(t, client, nodes, []string{"policy-public-" + mode + "@goauthy.e2e", "policy-admin-" + mode + "@goauthy.e2e"}, validValues)
}

func TestUserValuesPolicyPersisted(t *testing.T) {
	mode := os.Getenv("GOAUTHY_E2E_USER_VALUES_MODE")
	if mode == "" {
		t.Skip("set GOAUTHY_E2E_USER_VALUES_MODE")
	}
	if mode != "required" && mode != "optional" && mode != "hidden" {
		t.Fatalf("invalid GOAUTHY_E2E_USER_VALUES_MODE=%q", mode)
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := adminUpdateNodes(primary, secondary, os.Getenv("GOAUTHY_E2E_TERTIARY_URL"))
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), username, password, "policy-persisted-"+mode)
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	values := map[string]any{"birthdate": "2000-01-02", "phone": "+82101234", "street": "Main Street", "zip": "12345", "city": "Seoul", "country": "KR", "tz": "Asia/Seoul"}
	emails := []string{"policy-public-" + mode + "@goauthy.e2e", "policy-admin-" + mode + "@goauthy.e2e"}
	ids := assertUserValuesPolicyProfiles(t, client, nodes, emails, values)
	body := map[string]any{"email": emails[1], "family_name": "User", "roles": []string{}, "enabled": true, "email_verified": false, "user_values": values}
	payload, _ := json.Marshal(body)
	response := do(t, client, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(ids[emails[1]]), bytes.NewReader(payload), headers)
	response.Body.Close()
	want := http.StatusOK
	if mode == "required" {
		want = http.StatusBadRequest
	}
	if response.StatusCode != want {
		t.Fatalf("restarted mode=%s status=%d want=%d", mode, response.StatusCode, want)
	}
	if mode != "required" && readPolicyProfile(t, client, primary, ids[emails[1]])["given_name"] != nil {
		t.Fatal("restarted optional/hidden policy did not clear given name")
	}
	body["given_name"] = "Policy"
	payload, _ = json.Marshal(body)
	response = do(t, client, http.MethodPut, primary+"/auth/v1/users/"+url.PathEscape(ids[emails[1]]), bytes.NewReader(payload), headers)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("restore after restart status=%d", response.StatusCode)
	}
	assertUserValuesPolicyProfiles(t, client, nodes, emails, values)
}

func assertUserValuesPolicyProfiles(t *testing.T, client *http.Client, nodes []string, emails []string, expected map[string]any) map[string]string {
	t.Helper()
	ids := make(map[string]string, len(emails))
	for _, base := range nodes {
		response := do(t, client, http.MethodGet, base+"/auth/v1/users", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
		var users []struct{ ID, Email string }
		err := json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&users)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("user list node=%s status=%d err=%v", base, response.StatusCode, err)
		}
		for _, email := range emails {
			id := ""
			for _, user := range users {
				if user.Email == email {
					id = user.ID
					break
				}
			}
			if id == "" {
				t.Fatalf("profile %s missing on %s", email, base)
			}
			if prior := ids[email]; prior != "" && prior != id {
				t.Fatalf("profile identity differs on %s", base)
			}
			ids[email] = id
			response = do(t, client, http.MethodGet, base+"/auth/v1/users/"+url.PathEscape(id), nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
			var profile struct {
				Email      string         `json:"email"`
				GivenName  *string        `json:"given_name"`
				FamilyName *string        `json:"family_name"`
				UserValues map[string]any `json:"user_values"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&profile)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || err != nil || profile.Email != email || profile.GivenName == nil || *profile.GivenName != "Policy" || profile.FamilyName == nil || *profile.FamilyName != "User" {
				t.Fatalf("profile node=%s email=%s status=%d", base, email, response.StatusCode)
			}
			for key, value := range expected {
				if got, ok := profile.UserValues[key]; !ok || got != value {
					t.Fatalf("profile node=%s email=%s field=%s got=%v", base, email, key, got)
				}
			}
		}
	}
	return ids
}

func omitPolicyField(body map[string]any, field, variant string) {
	object := body
	if field != "given_name" && field != "family_name" {
		object = body["user_values"].(map[string]any)
	}
	switch variant {
	case "omitted":
		delete(object, field)
	case "null":
		object[field] = nil
	case "empty":
		object[field] = ""
	}
}

func readPolicyProfile(t *testing.T, client *http.Client, base, id string) map[string]any {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/"+url.PathEscape(id), nil, nil)
	defer response.Body.Close()
	var profile map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&profile); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("profile read node=%s status=%d decode=%v", base, response.StatusCode, err)
	}
	if _, ok := profile["user_values"].(map[string]any); !ok {
		t.Fatal("profile lacks user_values object")
	}
	return profile
}

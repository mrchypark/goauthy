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
)

func TestUserAttributesAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SELF_ATTRIBUTES") != "1" {
		t.Skip("set GOAUTHY_E2E_SELF_ATTRIBUTES=1 to run self-editable user-attribute E2E")
	}
	primary, secondary, tertiary, username, password, _ := rolesGroupsConfig(t)
	sinkURL := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if sinkURL == "" {
		t.Skip("set GOAUTHY_E2E_SMTP_SINK_URL to run self-editable user-attribute E2E")
	}
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)

	created := userAttributeCreate(t, admin, primary, csrf, userAttributeConfig{Name: "employee_id", Desc: stringPtr("Employee ID"), DefaultValue: json.RawMessage(`"E-000"`), UserEditable: true})
	userAttributeAssertConfigState(t, admin, secondary, created)
	private := userAttributeCreate(t, admin, tertiary, csrf, userAttributeConfig{Name: "private_note", Desc: stringPtr("Private note"), DefaultValue: json.RawMessage(`"private-default"`), UserEditable: false})

	memberEmail, memberSubject, memberPassword := registerSelfAttributeMember(t, primary, secondary, sinkURL)
	member, memberCSRF := rbacAuthenticatedClient(t, primary, secondary, memberEmail, memberPassword)
	userAttributeAssertEditable(t, member, secondary, memberSubject, []userAttributeConfig{editableAttribute(created, nil)}, "default")
	userAttributeAssertEditableForbidden(t, member, tertiary, "bootstrap-admin")
	userAttributeAssertPutCrossSiteForbidden(t, member, primary, memberCSRF, memberSubject)
	userAttributePutValues(t, member, primary, memberCSRF, memberSubject, []userAttributeValue{{Key: "employee_id", Value: json.RawMessage(`"E-123"`)}, {Key: "private_note", Value: json.RawMessage(`"private"`)}, {Key: "unknown_attr", Value: json.RawMessage(`true`)}}, []userAttributeValue{{Key: "employee_id", Value: json.RawMessage(`"E-123"`)}}, "non-admin filters private and unknown")
	userAttributeAssertEditable(t, member, tertiary, memberSubject, []userAttributeConfig{editableAttribute(created, json.RawMessage(`"E-123"`))}, "cross-pod persisted")
	userAttributePutValues(t, member, secondary, memberCSRF, memberSubject, []userAttributeValue{{Key: "employee_id", Value: json.RawMessage(`""`)}}, nil, "empty string deletes")
	userAttributeAssertEditable(t, member, primary, memberSubject, []userAttributeConfig{editableAttribute(created, nil)}, "cross-pod delete")

	userAttributeDelete(t, admin, tertiary, csrf, created.Name)
	userAttributeDelete(t, admin, primary, csrf, private.Name)
	userAttributeAssertEditable(t, member, tertiary, memberSubject, nil, "config delete replicated")
}

func registerSelfAttributeMember(t *testing.T, primary, secondary, sinkURL string) (email, subject, password string) {
	t.Helper()
	mailbox := &http.Client{}
	clearSMTPMailbox(t, mailbox, sinkURL)
	email = "self-attributes@goauthy.e2e"
	proof := solvePasswordResetPoW(t, passwordResetPoWChallenge(t, mailbox, primary), 10)
	body, err := json.Marshal(map[string]string{
		"email": email, "preferred_username": "self_attributes", "given_name": "Self", "family_name": "Attributes", "pow": proof, "redirect_uri": defaultRedirectURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, mailbox, http.MethodPost, primary+"/auth/v1/users/register", bytes.NewReader(body), map[string]string{"Content-Type": "application/json"})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("register self-edit member status=%d", response.StatusCode)
	}
	mail := waitForResetMail(t, mailbox, sinkURL, email)
	activationURL, err := url.Parse(mail.resetURL)
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(strings.Trim(activationURL.EscapedPath(), "/"), "/")
	if len(segments) != 6 || segments[2] != "users" || segments[4] != "reset" || segments[5] == "" {
		t.Fatalf("invalid self-edit activation URL %q", activationURL.EscapedPath())
	}
	subject, err = url.PathUnescape(segments[3])
	if err != nil || subject == "" {
		t.Fatalf("invalid self-edit subject %q: %v", segments[3], err)
	}
	activation := newBrowserClient(t)
	response = do(t, activation, http.MethodGet, mail.resetURL, nil, nil)
	var challenge struct {
		CSRFToken string `json:"csrf_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 4<<10)).Decode(&challenge)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || challenge.CSRFToken == "" {
		t.Fatalf("self-edit activation GET status=%d csrf=%t decode=%v", response.StatusCode, challenge.CSRFToken != "", err)
	}
	password = "Self-Attributes-Password-1A"
	body, err = json.Marshal(map[string]string{"magic_link_id": segments[5], "password": password})
	if err != nil {
		t.Fatal(err)
	}
	response = do(t, activation, http.MethodPut, secondary+"/auth/v1/users/"+url.PathEscape(subject)+"/reset", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": challenge.CSRFToken})
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("self-edit activation PUT status=%d", response.StatusCode)
	}
	return email, subject, password
}

type userAttributeConfig struct {
	Name         string          `json:"name"`
	Desc         *string         `json:"desc,omitempty"`
	DefaultValue json.RawMessage `json:"default_value,omitempty"`
	Type         *string         `json:"typ,omitempty"`
	UserEditable bool            `json:"user_editable"`
	Value        json.RawMessage `json:"value,omitempty"`
}

func editableAttribute(config userAttributeConfig, value json.RawMessage) userAttributeConfig {
	config.UserEditable = false
	config.Value = value
	return config
}

func userAttributeAssertEditable(t *testing.T, client *http.Client, base, subject string, want []userAttributeConfig, label string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/"+subject+"/attr/editable", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var payload struct {
		Values []userAttributeConfig `json:"values"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload)
	equal := reflect.DeepEqual(payload.Values, want) || len(payload.Values) == 0 && len(want) == 0
	if response.StatusCode != http.StatusOK || err != nil || !equal {
		t.Fatalf("editable %s status=%d got=%+v want=%+v decode=%v", label, response.StatusCode, payload.Values, want, err)
	}
}

func userAttributeAssertEditableForbidden(t *testing.T, client *http.Client, base, subject string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/"+subject+"/attr/editable", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-subject editable status=%d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func userAttributeAssertPutCrossSiteForbidden(t *testing.T, client *http.Client, base, csrf, subject string) {
	t.Helper()
	response := do(t, client, http.MethodPut, base+"/auth/v1/users/"+subject+"/attr", bytes.NewReader([]byte(`{"values":[]}`)), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site", "X-CSRF-Token": csrf})
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-site self attribute update status=%d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

type userAttributeValue struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

func userAttributeCreate(t *testing.T, client *http.Client, base, csrf string, want userAttributeConfig) userAttributeConfig {
	t.Helper()
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/attr", userAttributeConfigBody(t, want), rbacMutationHeaders(csrf))
	defer response.Body.Close()
	var got userAttributeConfig
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&got); response.StatusCode != http.StatusOK || err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("create status=%d got=%+v want=%+v decode=%v", response.StatusCode, got, want, err)
	}
	return got
}

func userAttributeRename(t *testing.T, client *http.Client, base, csrf, name string, want userAttributeConfig) userAttributeConfig {
	t.Helper()
	response := do(t, client, http.MethodPut, base+"/auth/v1/users/attr/"+name, userAttributeConfigBody(t, want), rbacMutationHeaders(csrf))
	defer response.Body.Close()
	var got userAttributeConfig
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&got); response.StatusCode != http.StatusOK || err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("rename status=%d got=%+v want=%+v decode=%v", response.StatusCode, got, want, err)
	}
	return got
}

func userAttributeDelete(t *testing.T, client *http.Client, base, csrf, name string) {
	t.Helper()
	response := do(t, client, http.MethodDelete, base+"/auth/v1/users/attr/"+name, nil, rbacMutationHeaders(csrf))
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete status=%d", response.StatusCode)
	}
}

func userAttributeAssertConfigState(t *testing.T, client *http.Client, base string, want userAttributeConfig) {
	t.Helper()
	userAttributeAssertConfigs(t, client, base, []userAttributeConfig{want})
}

func userAttributeAssertConfigs(t *testing.T, client *http.Client, base string, want []userAttributeConfig) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/attr", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var payload struct {
		Values []userAttributeConfig `json:"values"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload)
	equal := reflect.DeepEqual(payload.Values, want) || len(payload.Values) == 0 && len(want) == 0
	if response.StatusCode != http.StatusOK || err != nil || !equal {
		t.Fatalf("config list status=%d got=%+v want=%+v decode=%v", response.StatusCode, payload.Values, want, err)
	}
}

func userAttributePutValues(t *testing.T, client *http.Client, base, csrf, subject string, values, want []userAttributeValue, label string) {
	t.Helper()
	body, err := json.Marshal(struct {
		Values []userAttributeValue `json:"values"`
	}{Values: values})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPut, base+"/auth/v1/users/"+subject+"/attr", bytes.NewReader(body), rbacMutationHeaders(csrf))
	defer response.Body.Close()
	var payload struct {
		Values []userAttributeValue `json:"values"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload)
	equal := reflect.DeepEqual(payload.Values, want) || len(payload.Values) == 0 && len(want) == 0
	if response.StatusCode != http.StatusOK || err != nil || !equal {
		t.Fatalf("%s status=%d got=%+v want=%+v decode=%v", label, response.StatusCode, payload.Values, want, err)
	}
}

func userAttributeAssertValues(t *testing.T, client *http.Client, base, subject string, want []userAttributeValue, label string) {
	t.Helper()
	response := do(t, client, http.MethodGet, base+"/auth/v1/users/"+subject+"/attr", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	var payload struct {
		Values []userAttributeValue `json:"values"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload)
	equal := reflect.DeepEqual(payload.Values, want) || len(payload.Values) == 0 && len(want) == 0
	if response.StatusCode != http.StatusOK || err != nil || !equal {
		t.Fatalf("%s status=%d got=%+v want=%+v decode=%v", label, response.StatusCode, payload.Values, want, err)
	}
}

func userAttributeConfigBody(t *testing.T, value userAttributeConfig) io.Reader {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(body)
}

func stringPtr(value string) *string { return &value }

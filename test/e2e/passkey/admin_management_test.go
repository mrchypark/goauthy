package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPasskeyListWireRejectsMalformed(t *testing.T) {
	for _, body := range []string{`null`, `[{"Name":"x","registered":1,"last_used":0}]`, `[{"name":"x","registered":1}]`, `[{"name":"x","registered":"1","last_used":0}]`, `[{"name":"x","registered":1,"last_used":null}]`, `[{"name":"x","registered":1,"last_used":0,"user_verified":null}]`, `[{"name":"x","registered":1,"last_used":0,"extra":true}]`} {
		if err := validatePasskeyList([]byte(body), "x", 1, false); err == nil {
			t.Errorf("accepted malformed passkey list %s", body)
		}
	}
	if err := validatePasskeyList([]byte(`[]`), "", 0, false); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`[{"name":"x","registered":1,"last_used":0}]`, `[{"name":"x","registered":1,"last_used":0,"user_verified":false}]`, `[{"name":"x","registered":1,"last_used":0,"user_verified":true}]`} {
		if err := validatePasskeyList([]byte(body), "x", 1, false); err != nil {
			t.Fatalf("rejected valid neighbor: %v", err)
		}
	}
	if err := validatePasskeyList([]byte(`[{"name":"x","registered":1,"last_used":0,"user_verified":false}]`), "x", 1, true); err == nil {
		t.Fatal("accepted a non-UV credential in force-UV fixture")
	}
}

func validatePasskeyList(body []byte, wantName string, wantCount int, requireUV bool) error {
	var rows []json.RawMessage
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) || json.Unmarshal(body, &rows) != nil || len(rows) != wantCount {
		return fmt.Errorf("invalid passkey list")
	}
	for _, raw := range rows {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return fmt.Errorf("invalid passkey row")
		}
		if len(fields) < 3 || len(fields) > 4 {
			return fmt.Errorf("unexpected passkey keys")
		}
		for key := range fields {
			if key != "name" && key != "registered" && key != "last_used" && key != "user_verified" {
				return fmt.Errorf("unknown key %s", key)
			}
		}
		for _, key := range []string{"name", "registered", "last_used"} {
			if _, ok := fields[key]; !ok {
				return fmt.Errorf("missing %s", key)
			}
			if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
				return fmt.Errorf("null %s", key)
			}
		}
		var name string
		var registered, lastUsed int64
		if json.Unmarshal(fields["name"], &name) != nil || name != wantName || json.Unmarshal(fields["registered"], &registered) != nil || registered <= 0 || json.Unmarshal(fields["last_used"], &lastUsed) != nil || lastUsed < 0 {
			return fmt.Errorf("invalid passkey fields")
		}
		if uv, ok := fields["user_verified"]; ok {
			var value bool
			if bytes.Equal(bytes.TrimSpace(uv), []byte("null")) || json.Unmarshal(uv, &value) != nil || (requireUV && !value) {
				return fmt.Errorf("invalid user_verified")
			}
		} else if requireUV {
			return fmt.Errorf("missing user_verified")
		}
	}
	return nil
}

// TestAdminPasskeyManagementAcrossPods covers API-key read-only access and the
// self-service MFA-protected deletion path. It is opt-in because it needs
// Chrome's virtual authenticator and a dedicated cluster.
func TestAdminPasskeyManagementAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ADMIN_PASSKEY") != "1" {
		t.Skip("set GOAUTHY_E2E_ADMIN_PASSKEY=1 to run admin passkey E2E")
	}
	primary := requiredURL(t, "GOAUTHY_E2E_URL")
	secondary := requiredURL(t, "GOAUTHY_E2E_SECONDARY_URL")
	tertiary := requiredURL(t, "GOAUTHY_E2E_TERTIARY_URL")
	username := requiredEnv(t, "GOAUTHY_E2E_BROWSER_USERNAME")
	password := requiredEnv(t, "GOAUTHY_E2E_BROWSER_PASSWORD")
	subject := requiredEnv(t, "GOAUTHY_E2E_BROWSER_SUBJECT")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	auth := newVirtualAuthenticator(t, ctx)
	defer auth.close()
	client := browserClient(t)
	loginPassword(t, client, primary, username, password, "admin-passkey-reset")
	csrf := accountCSRF(t, client, primary)
	modification := issueModification(t, client, primary, subject, csrf, password)
	registration := beginRegistrationNamed(t, client, secondary, subject, csrf, "Admin reset key", modification)
	setChromeCookies(t, auth.ctx, primary, client.Jar.Cookies(mustURL(t, primary+"/auth/v1/users/")))
	finishAdminRegistration(t, client, tertiary, subject, csrf, webauthnCreate(t, auth.ctx, primary, registration))

	secret := createUsersReaderKey(t, client, primary, csrf)
	assertUserList(t, client, secret, []string{primary, secondary, tertiary}, subject)
	assertUserDetail(t, client, secret, []string{primary, secondary, tertiary}, subject)
	apiList := do(t, browserClient(t), http.MethodGet, secondary+"/auth/v1/users/"+subject+"/webauthn", nil, map[string]string{"Authorization": "API-Key " + secret})
	listBody, err := io.ReadAll(io.LimitReader(apiList.Body, 16<<10))
	apiList.Body.Close()
	if apiList.StatusCode != http.StatusOK || err != nil || validatePasskeyList(listBody, "Admin reset key", 1, true) != nil {
		t.Fatalf("API passkey list status=%d contains=%t read=%v", apiList.StatusCode, bytes.Contains(listBody, []byte(`"name":"Admin reset key"`)), err)
	}
	for _, base := range []string{primary, tertiary} {
		response := do(t, browserClient(t), http.MethodGet, base+"/auth/v1/users/"+subject+"/webauthn", nil, map[string]string{"Authorization": "API-Key " + secret})
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 16<<10))
		response.Body.Close()
		if response.StatusCode != http.StatusOK || readErr != nil || validatePasskeyList(body, "Admin reset key", 1, true) != nil {
			t.Fatalf("replicated passkey list status=%d node=%s", response.StatusCode, base)
		}
	}
	apiDelete := do(t, browserClient(t), http.MethodDelete, tertiary+"/auth/v1/users/"+subject+"/webauthn/delete/Admin%20reset%20key", nil, map[string]string{"Authorization": "API-Key " + secret})
	apiDelete.Body.Close()
	if apiDelete.StatusCode != http.StatusForbidden {
		t.Fatalf("API passkey delete status=%d, want 403", apiDelete.StatusCode)
	}

	deleteCSRF := accountCSRF(t, client, secondary)
	proofStart := beginMFAProof(t, client, secondary, subject, deleteCSRF)
	proofAssertion := webauthnGet(t, auth.ctx, tertiary, proofStart.RCR)
	if status, proof := finishMFAProof(t, client, tertiary, subject, deleteCSRF, proofStart.Code, proofAssertion); status != http.StatusAccepted {
		t.Fatalf("self delete MFA proof status=%d", status)
	} else if status, modification := modificationToken(t, client, primary, subject, accountCSRF(t, client, primary), map[string]string{"mfa_code": proof.Code}); status != http.StatusOK {
		t.Fatalf("self delete modification token status=%d", status)
	} else {
		body, _ := json.Marshal(map[string]string{"mfa_mod_token_id": modification})
		reset := do(t, client, http.MethodDelete, secondary+"/auth/v1/users/"+subject+"/webauthn/delete/Admin%20reset%20key", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": accountCSRF(t, client, secondary)})
		reset.Body.Close()
		if reset.StatusCode != http.StatusOK {
			t.Fatalf("self passkey delete status=%d", reset.StatusCode)
		}
	}
	for _, base := range []string{primary, secondary, tertiary} {
		verify := do(t, client, http.MethodGet, base+"/auth/v1/users/"+subject+"/webauthn", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
		remaining, err := io.ReadAll(io.LimitReader(verify.Body, 16<<10))
		verify.Body.Close()
		if verify.StatusCode != http.StatusOK || err != nil || !bytes.Equal(bytes.TrimSpace(remaining), []byte("[]")) {
			t.Fatalf("self delete replication status=%d node=%s read=%v", verify.StatusCode, base, err)
		}
	}
	revoke := do(t, client, http.MethodDelete, primary+"/auth/v1/api_keys/passkey-reader", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": accountCSRF(t, client, primary)})
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("revoke users API key status=%d", revoke.StatusCode)
	}
	for _, base := range []string{primary, secondary, tertiary} {
		gone := do(t, browserClient(t), http.MethodGet, base+"/auth/v1/users?page_size=1", nil, map[string]string{"Authorization": "API-Key " + secret})
		gone.Body.Close()
		if gone.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked users API key status=%d node=%s", gone.StatusCode, base)
		}
		detail := do(t, browserClient(t), http.MethodGet, base+"/auth/v1/users/"+subject, nil, map[string]string{"Authorization": "API-Key " + secret})
		detail.Body.Close()
		if detail.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked detail status=%d node=%s", detail.StatusCode, base)
		}
	}
}

func assertUserDetail(t *testing.T, session *http.Client, secret string, bases []string, subject string) {
	t.Helper()
	var reference []byte
	for _, base := range bases {
		for _, tc := range []struct {
			auth string
			c    *http.Client
		}{{"", session}, {"API-Key " + secret, browserClient(t)}} {
			h := map[string]string{"Sec-Fetch-Site": "same-origin"}
			if tc.auth != "" {
				h["Authorization"] = tc.auth
			}
			r := do(t, tc.c, http.MethodGet, base+"/auth/v1/users/"+subject, nil, h)
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if r.StatusCode != http.StatusOK {
				t.Fatalf("user detail status=%d", r.StatusCode)
			}
			if err := validateUserDetail(b, subject); err != nil {
				t.Fatalf("user detail node=%s: %v", base, err)
			}
			if reference == nil {
				reference = b
			} else if !bytes.Equal(reference, b) {
				t.Fatalf("user detail projections differ node=%s", base)
			}
		}
	}
	for _, base := range bases {
		r := do(t, browserClient(t), http.MethodGet, base+"/auth/v1/users/"+subject, nil, nil)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous detail status=%d", r.StatusCode)
		}
		r = do(t, session, http.MethodGet, base+"/auth/v1/users/"+subject, nil, map[string]string{"Authorization": "Bearer malformed"})
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("malformed detail status=%d", r.StatusCode)
		}
	}
}

func validateUserDetail(body []byte, subject string) error {
	var row map[string]json.RawMessage
	if json.Unmarshal(body, &row) != nil || row["id"] == nil {
		return fmt.Errorf("invalid detail")
	}
	for name, value := range row {
		switch name {
		case "id", "email", "language", "enabled", "email_verified", "account_type", "created_at", "last_login", "roles", "user_values", "password_expires", "webauthn_user_id":
		default:
			return fmt.Errorf("unexpected detail field %s", name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("null detail field %s", name)
		}
	}
	var verified bool
	if json.Unmarshal(row["email_verified"], &verified) != nil || verified {
		return fmt.Errorf("email_verified")
	}
	if value, exists := row["password_expires"]; exists {
		var expires int64
		if json.Unmarshal(value, &expires) != nil || expires <= 0 {
			return fmt.Errorf("password_expires")
		}
	}
	if value, exists := row["webauthn_user_id"]; exists {
		var handle string
		if json.Unmarshal(value, &handle) != nil || handle == "" {
			return fmt.Errorf("webauthn_user_id")
		}
	}
	var id, email, language, account string
	var enabled bool
	var created, login int64
	if json.Unmarshal(row["id"], &id) != nil || id != subject || json.Unmarshal(row["email"], &email) != nil || email != "" || json.Unmarshal(row["language"], &language) != nil || language != "en" || json.Unmarshal(row["enabled"], &enabled) != nil || !enabled || json.Unmarshal(row["account_type"], &account) != nil || account != "password" || json.Unmarshal(row["created_at"], &created) != nil || created <= 0 || json.Unmarshal(row["last_login"], &login) != nil || login <= 0 {
		return fmt.Errorf("invalid detail fields")
	}
	var roles []string
	if json.Unmarshal(row["roles"], &roles) != nil || !slices.Contains(roles, "rauthy_admin") {
		return fmt.Errorf("roles")
	}
	if string(row["user_values"]) != "{}" {
		return fmt.Errorf("user_values")
	}
	return nil
}

func TestUserDetailWireRejectsMalformed(t *testing.T) {
	valid := `{"id":"subject","email":"","email_verified":false,"language":"en","enabled":true,"account_type":"password","created_at":1,"last_login":1,"roles":["rauthy_admin"],"user_values":{}}`
	if validateUserDetail([]byte(valid), "subject") != nil {
		t.Fatal("valid detail rejected")
	}
	for _, body := range []string{`null`, `{"id":"subject"}`, strings.Replace(valid, `"email":""`, `"email":null`, 1), strings.Replace(valid, `"created_at":1`, `"created_at":"1"`, 1), strings.Replace(valid, `"email_verified":false,`, "", 1), strings.Replace(valid, `"user_values":{}`, `"user_values":{},"password_phc":"private"`, 1), strings.Replace(valid, `"user_values":{}`, `"user_values":{},"webauthn_user_id":null`, 1)} {
		if validateUserDetail([]byte(body), "subject") == nil {
			t.Errorf("accepted malformed detail %s", body)
		}
	}
}

func assertUserList(t *testing.T, session *http.Client, secret string, bases []string, subject string) {
	t.Helper()
	threshold := 200
	if raw := os.Getenv("GOAUTHY_E2E_USER_LIST_THRESHOLD"); raw != "" {
		var err error
		threshold, err = strconv.Atoi(raw)
		if err != nil || (threshold != 1 && threshold != 200) {
			t.Fatal("user list E2E threshold must be 1 or 200")
		}
	}
	wantStatus := http.StatusOK
	if threshold == 1 {
		wantStatus = http.StatusPartialContent
	}
	var reference []byte
	for _, base := range bases {
		for _, tc := range []struct {
			name, auth string
			client     *http.Client
		}{{"browser", "", session}, {"api", "API-Key " + secret, browserClient(t)}} {
			headers := map[string]string{"Sec-Fetch-Site": "same-origin"}
			if tc.auth != "" {
				headers["Authorization"] = tc.auth
			}
			r := do(t, tc.client, http.MethodGet, base+"/auth/v1/users?page_size=1", nil, headers)
			body, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
			r.Body.Close()
			if r.StatusCode != wantStatus || err != nil || r.Header.Get("X-User-Count") != "1" {
				t.Fatalf("users %s status=%d", tc.name, r.StatusCode)
			}
			if err := validateUserList(body, subject, 1); err != nil {
				t.Fatalf("users %s node=%s: %v", tc.name, base, err)
			}
			if reference == nil {
				reference = body
			} else if !bytes.Equal(reference, body) {
				t.Fatalf("browser/API user projections differ on %s", base)
			}
		}
	}
	for _, base := range bases {
		r := do(t, browserClient(t), http.MethodGet, base+"/auth/v1/users?page_size=1", nil, nil)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous users status=%d", r.StatusCode)
		}
		r = do(t, session, http.MethodGet, base+"/auth/v1/users?page_size=1", nil, map[string]string{"Authorization": "Bearer malformed"})
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("invalid API key users status=%d", r.StatusCode)
		}
	}
	for _, base := range bases {
		r := do(t, browserClient(t), http.MethodGet, base+"/auth/v1/users?page_size=1", nil, map[string]string{"Authorization": "API-Key " + secret})
		r.Body.Close()
		if r.StatusCode != wantStatus || r.Header.Get("X-User-Count") != "1" {
			t.Fatalf("users threshold status=%d node=%s", r.StatusCode, base)
		}
		if threshold == 1 && (r.Header.Get("X-Page-Size") != "1" || r.Header.Get("X-Page-Count") != "1") {
			t.Fatalf("missing pagination headers node=%s", base)
		}
	}
	if threshold == 1 {
		r := do(t, browserClient(t), http.MethodGet, bases[0]+"/auth/v1/users?page_size=1", nil, map[string]string{"Authorization": "API-Key " + secret})
		r.Body.Close()
		cursor := r.Header.Get("X-Continuation-Token")
		if cursor == "" || r.Header.Get("X-User-Count") != "1" || r.Header.Get("X-Page-Count") != "1" {
			t.Fatal("missing user pagination headers")
		}
		for _, query := range []string{"continuation_token=" + url.QueryEscape(cursor), "backwards=true&continuation_token=" + url.QueryEscape(cursor)} {
			for _, base := range bases {
				next := do(t, browserClient(t), http.MethodGet, base+"/auth/v1/users?page_size=1&"+query, nil, map[string]string{"Authorization": "API-Key " + secret})
				b, _ := io.ReadAll(next.Body)
				next.Body.Close()
				if next.StatusCode != http.StatusPartialContent || next.Header.Get("X-User-Count") != "1" || next.Header.Get("X-Page-Size") != "1" || next.Header.Get("X-Page-Count") != "1" || next.Header.Get("X-Continuation-Token") != "" || !bytes.Equal(bytes.TrimSpace(b), []byte("[]")) {
					t.Fatalf("user cursor status=%d node=%s body=%s", next.StatusCode, base, b)
				}
			}
		}
	}
}

func validateUserList(body []byte, subject string, count int) error {
	var rows []map[string]json.RawMessage
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) || json.Unmarshal(body, &rows) != nil || len(rows) != count {
		return fmt.Errorf("invalid user list")
	}
	for _, row := range rows {
		if len(row) != 7 {
			return fmt.Errorf("user fields=%d", len(row))
		}
		for k := range row {
			switch k {
			case "id", "email", "given_name", "family_name", "created_at", "last_login", "picture_id":
			default:
				return fmt.Errorf("unknown field %s", k)
			}
		}
		var id, got string
		if json.Unmarshal(row["id"], &id) != nil || id != subject || bytes.Equal(bytes.TrimSpace(row["email"]), []byte("null")) || json.Unmarshal(row["email"], &got) != nil || got != "" {
			return fmt.Errorf("id/email")
		}
		for _, key := range []string{"given_name", "family_name"} {
			var value string
			if string(row[key]) != "null" && json.Unmarshal(row[key], &value) != nil {
				return fmt.Errorf("%s", key)
			}
		}
		if string(row["picture_id"]) != "null" {
			var value string
			if json.Unmarshal(row["picture_id"], &value) != nil {
				return fmt.Errorf("picture_id")
			}
		}
		var created, login int64
		if json.Unmarshal(row["created_at"], &created) != nil || created <= 0 || json.Unmarshal(row["last_login"], &login) != nil || login <= 0 {
			return fmt.Errorf("timestamps")
		}
	}
	return nil
}

func TestUserListWireRejectsMalformed(t *testing.T) {
	if err := validateUserList([]byte(`[{"id":"subject","email":"","given_name":null,"family_name":"","created_at":1,"last_login":1,"picture_id":null}]`), "subject", 1); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`null`, `[{"email":"x"}]`, `[{"Email":"x","id":"i","given_name":"","family_name":"","created_at":1,"last_login":1,"picture_id":null}]`, `[{"id":"i","email":"x","given_name":"","family_name":"","created_at":"1","last_login":1,"picture_id":null}]`, `[{"id":"i","email":"x","given_name":"","family_name":"","created_at":1,"last_login":1,"picture_id":null,"extra":1}]`} {
		if validateUserList([]byte(body), "x", 1) == nil {
			t.Errorf("accepted malformed %s", body)
		}
	}
}

func finishAdminRegistration(t *testing.T, client *http.Client, base, subject, csrf string, data json.RawMessage) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"passkey_name": "Admin reset key", "data": data})
	response := do(t, client, http.MethodPost, base+"/auth/v1/users/"+subject+"/webauthn/register/finish", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("admin passkey registration finish status=%d", response.StatusCode)
	}
}

func createUsersReaderKey(t *testing.T, client *http.Client, base, csrf string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": "passkey-reader", "access": []map[string]any{{"group": "Users", "access_rights": []string{"read"}}}})
	response := do(t, client, http.MethodPost, base+"/auth/v1/api_keys", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	secret, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || len(secret) == 0 {
		t.Fatalf("create users reader status=%d secret=%d read=%v", response.StatusCode, len(secret), err)
	}
	return string(secret)
}

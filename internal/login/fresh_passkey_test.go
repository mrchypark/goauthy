package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func bootstrapPasskeyOnlyUser(t *testing.T, db *rhiza.DB, subject, username string) {
	t.Helper()
	ctx := context.Background()
	// Bootstrap creates a password-mode user; then we flip it to passkey-only.
	h := mustHash(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-test-passkey-bootstrap",
		SQL:       `INSERT OR IGNORE INTO identity_users (subject, username, password_phc, password_changed_at_unix_ms, password_generation, created_at_unix_ms) VALUES (?,?,?,?,1,?)`,
		Args:      []any{subject, username, h, 0, 0},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-test-passkey-mode",
		SQL:       `INSERT OR IGNORE INTO identity_authentication_modes (subject, mode, generation, updated_at_unix_ms) VALUES (?, 'passkey', 1, 0)`,
		Args:      []any{subject},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-test-passkey-clear",
		SQL:       `UPDATE identity_users SET password_phc='' WHERE subject=?`,
		Args:      []any{subject},
	}); err != nil {
		t.Fatal(err)
	}
}

func mustHash(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	h, err := testHash(ctx, []byte("dummy"))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestWebAuthnStartPasskeyOnlyAbsentCookieNoUsernameDenies(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	body, _ := json.Marshal(passkeyStartRequest{
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestWebAuthnStartPasskeyOnlyTamperedCookieDenies(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	valid, err := h.passkeys.PasswordlessCookie("user-1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(passkeyStartRequest{
		Username: "alice",
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)
	r.AddCookie(&http.Cookie{Name: h.passkeyCookieName(), Value: valid + "x"})

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestWebAuthnStartPasskeyOnlyUnknownUserDenies(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	body, _ := json.Marshal(passkeyStartRequest{
		Username: "nobody",
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestWebAuthnStartPasskeyOnlyPasswordModeUserDenies(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	// "alice" is a password-mode user (bootstrapped by testHandler).
	body, _ := json.Marshal(passkeyStartRequest{
		Username: "alice",
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestWebAuthnStartPasskeyOnlyWrongInteractionDenies(t *testing.T) {
	t.Parallel()
	h, db := testHandlerWithDB(t, false)

	// Create a passkey-only user.
	bootstrapPasskeyOnlyUser(t, db, "passkey-only-subject", "passkey-only")

	// Init session.
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]

	// Use a fake interaction token.
	body, _ := json.Marshal(passkeyStartRequest{
		Username: "passkey-only",
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: "x"},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestWebAuthnStartPasskeyOnlyDisabledUserDenies(t *testing.T) {
	t.Parallel()
	h := testHandler(t)

	// "disabled" user exists but is disabled.
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	body, _ := json.Marshal(passkeyStartRequest{
		Username: "disabled",
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestWebAuthnStartValidUsernameEmptyCookieDenies(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	body, _ := json.Marshal(passkeyStartRequest{
		Username: "alice",
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)
	// Empty passkey cookie value should be rejected.
	r.AddCookie(&http.Cookie{Name: h.passkeyCookieName(), Value: ""})

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func credentialEnvelopePurpose(subject string) string {
	d := sha256.Sum256([]byte(subject))
	return "passkey/credential/" + base64.RawURLEncoding.EncodeToString(d[:])
}

func TestWebAuthnStartFreshPasskeyOnlyUserRequiresUserVerification(t *testing.T) {
	t.Parallel()
	h, db := testHandlerWithDB(t, false)
	subject := "passkey-only-subject"

	bootstrapPasskeyOnlyUser(t, db, subject, "passkey-only")

	credIDBytes := []byte("cred-fresh-passkey")
	cred := wa.Credential{ID: credIDBytes, PublicKey: []byte("public-key-bytes")}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	kr := testOIDCKeyring(t)
	purpose := credentialEnvelopePurpose(subject)
	envelope, err := kr.SealEnvelope(purpose, credJSON)
	if err != nil {
		t.Fatal(err)
	}
	credIDB64 := base64.RawURLEncoding.EncodeToString(credIDBytes)
	envelopeB64 := base64.RawURLEncoding.EncodeToString(envelope)
	handle := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("u", 32)))

	ctx := context.Background()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-test-passkey-user-handle",
		SQL:       `INSERT OR IGNORE INTO identity_webauthn_users (subject, user_handle, created_at_unix_ms) VALUES (?, ?, 0)`,
		Args:      []any{subject, handle},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-test-passkey-cred",
		SQL:       `INSERT OR IGNORE INTO identity_webauthn_credentials (credential_id, subject, name, credential_json, sign_count, user_verified, registered_at_unix_ms, last_used_at_unix_ms) VALUES (?, ?, ?, ?, 0, 1, 0, 0)`,
		Args:      []any{credIDB64, subject, "default", envelopeB64},
	}); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	body, _ := json.Marshal(passkeyStartRequest{
		Username: "passkey-only",
		Purpose: struct {
			Login string `json:"Login"`
		}{Login: interaction},
	})
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(init)

	response := httptest.NewRecorder()
	h.WebAuthnStart(response, r)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}

	type rcrResponse struct {
		Code string                       `json:"code"`
		RCR  protocol.CredentialAssertion `json:"rcr"`
	}
	var result rcrResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode err=%v", err)
	}
	if result.Code == "" {
		t.Fatalf("empty code: %+v", result)
	}
	if result.RCR.Response.UserVerification != protocol.VerificationRequired {
		t.Fatalf("userVerification=%q want required", result.RCR.Response.UserVerification)
	}
}

func TestApprovalLateMFAOffersNativeBrowserContinuation(t *testing.T) {
	t.Parallel()
	for _, accept := range []string{"text/html,application/xhtml+xml", "application/json"} {
		t.Run(accept, func(t *testing.T) {
			h, db := testHandlerWithDB(t, false)
			h.issuer = "http://localhost/identity"
			ctx := context.Background()
			credentialID := []byte("late-policy-key")
			encoded, err := json.Marshal(wa.Credential{ID: credentialID, PublicKey: []byte("public-key-bytes")})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := testOIDCKeyring(t).SealEnvelope(credentialEnvelopePurpose("user-1"), encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "late-policy-user", SQL: "INSERT INTO identity_webauthn_users(subject,user_handle,created_at_unix_ms) VALUES('user-1',?,0)", Args: []any{base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("u", 32)))}}); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "late-policy-key", SQL: "INSERT INTO identity_webauthn_credentials(credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES(?,'user-1','key',?,0,1,0,0)", Args: []any{base64.RawURLEncoding.EncodeToString(credentialID), base64.RawURLEncoding.EncodeToString(envelope)}}); err != nil {
				t.Fatal(err)
			}
			page := httptest.NewRecorder()
			h.DeviceLoginHandler(false).ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/oidc/device/login?user_code=AB12CD34", nil))
			if page.Code != http.StatusOK {
				t.Fatalf("page=%d", page.Code)
			}
			if strings.Contains(page.Body.String(), "new URLSearchParams(new FormData(loginForm))") {
				t.Fatal("page was already forced MFA")
			}
			cookie := page.Result().Cookies()[0]
			interaction := interactionToken(t, page.Body.String())
			csrf := fedCMCSRFPattern.FindStringSubmatch(page.Body.String())
			if len(csrf) != 2 {
				t.Fatal("missing csrf")
			}
			h.SetApprovalForceMFA(true)
			form := url.Values{"interaction": {interaction}, "csrf_token": {csrf[1]}, "username": {"alice"}, "password": {"correct password"}}
			r := httptest.NewRequest(http.MethodPost, "/oidc/device/login", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Accept", accept)
			r.AddCookie(cookie)
			result := httptest.NewRecorder()
			h.DeviceLoginHandler(false).ServeHTTP(result, r)
			if result.Code != http.StatusOK || len(result.Result().Cookies()) != 0 {
				t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
			}
			if _, err := h.browser.LoadAuthorizationInteractionReadOnly(ctx, cookie.Value, interaction); err != nil {
				t.Fatalf("challenge consumed login: %v", err)
			}
			if accept == "application/json" {
				var response passkeyStartResponse
				if json.Unmarshal(result.Body.Bytes(), &response) != nil || response.Code == "" || response.RCR == nil {
					t.Fatalf("JSON contract lost: %s", result.Body.String())
				}
				return
			}
			if !strings.HasPrefix(result.Header().Get("Content-Type"), "text/html") {
				t.Fatal("native form reached JSON")
			}
			for _, want := range []string{`id="passkey-challenge-btn"`, `navigator.credentials.get`, `/identity/auth/v1/users/webauthn_finish`, `"userVerification":"required"`} {
				if !strings.Contains(result.Body.String(), want) {
					t.Fatalf("challenge missing %s: %s", want, result.Body.String())
				}
			}
			if strings.Contains(result.Body.String(), `name="password"`) || !strings.Contains(result.Header().Get("Content-Security-Policy"), "script-src 'nonce-") {
				t.Fatal("invalid challenge page or CSP")
			}
		})
	}
}

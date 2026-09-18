package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/credential"
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
	h, err := credential.Hash([]byte("dummy"))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestWebAuthnStartPasskeyOnlyAbsentCookieNoUsernameDenies(t *testing.T) {
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

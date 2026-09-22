package login

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// Exercise the real WebAuthn verifier with an independently signed assertion,
// rather than accepting a challenge response as proof of successful login.
func TestApprovalPasskeySignedCompletion(t *testing.T) {
	t.Parallel()
	for _, destination := range []string{"device", "handoff"} {
		for _, mode := range []string{"passkey-only", "password-mfa"} {
			for _, proof := range []string{"valid", "missing-uv", "bad-signature"} {
				t.Run(destination+"/"+mode+"/"+proof, func(t *testing.T) {
					h, db := testHandlerWithDB(t, false)
					subject := "user-1"
					if mode == "passkey-only" {
						subject = "passkey-approval"
						bootstrapPasskeyOnlyUser(t, db, subject, "passkey-owner")
					}
					key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					publicKey, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
					if err != nil {
						t.Fatal(err)
					}
					credentialID := []byte("approval-test-credential")
					b64 := base64.RawURLEncoding.EncodeToString
					credentialJSON, err := json.Marshal(wa.Credential{ID: credentialID, PublicKey: publicKey})
					if err != nil {
						t.Fatal(err)
					}
					envelope, err := testOIDCKeyring(t).SealEnvelope(credentialEnvelopePurpose(subject), credentialJSON)
					if err != nil {
						t.Fatal(err)
					}
					userHandle := []byte(strings.Repeat("u", 32))
					_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "signed-passkey-fixture", Statements: []rhiza.SQLStatement{
						{SQL: `INSERT INTO identity_webauthn_users(subject,user_handle,created_at_unix_ms) VALUES(?,?,0)`, Args: []any{subject, b64(userHandle)}},
						{SQL: `INSERT INTO identity_webauthn_credentials(credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms) VALUES(?,?,?, ?,0,1,0,0)`, Args: []any{b64(credentialID), subject, "signed fixture", b64(envelope)}},
					}})
					if err != nil {
						t.Fatal(err)
					}
					code := "AB12CD34"
					saved := approvalLoginInteraction{Purpose: approvalLoginPayload, ForceMFA: true, HandoffID: testHandoffID}
					want := h.issuer + "/account/connection-handoffs/" + testHandoffID
					if destination == "device" {
						saved.HandoffID = ""
						saved.DeviceCode = &code
						want = h.issuer + "/oidc/device/verify?user_code=" + code
					}
					cookie, interaction := approvalInteraction(t, h, saved)
					body, _ := json.Marshal(map[string]any{"username": "passkey-owner", "purpose": map[string]string{"Login": interaction}})
					request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_start", strings.NewReader(string(body)))
					request.Header.Set("Content-Type", "application/json")
					request.AddCookie(cookie)
					start := httptest.NewRecorder()
					if mode == "password-mfa" {
						h.Login(start, postLogin(cookie, interaction, "alice", "correct password"))
					} else {
						h.WebAuthnStart(start, request)
					}
					if start.Code != http.StatusOK {
						t.Fatalf("start=%d %s", start.Code, start.Body.String())
					}
					var challenge struct {
						Code string                       `json:"code"`
						RCR  protocol.CredentialAssertion `json:"rcr"`
					}
					if err := json.Unmarshal(start.Body.Bytes(), &challenge); err != nil {
						t.Fatal(err)
					}
					clientData, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": b64(challenge.RCR.Response.Challenge), "origin": h.issuer, "crossOrigin": false})
					rpHash := sha256.Sum256([]byte("localhost"))
					flags := byte(5) // User presence and verification.
					if proof == "missing-uv" {
						flags = 1
					}
					authenticatorData := append(rpHash[:], flags, 0, 0, 0, 1)
					clientHash := sha256.Sum256(clientData)
					signed := append(append([]byte{}, authenticatorData...), clientHash[:]...)
					digest := sha256.Sum256(signed)
					signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
					if err != nil {
						t.Fatal(err)
					}
					if proof == "bad-signature" {
						signature[len(signature)-1] ^= 1
					}
					assertion, _ := json.Marshal(map[string]any{"id": b64(credentialID), "rawId": b64(credentialID), "type": "public-key", "response": map[string]string{"authenticatorData": b64(authenticatorData), "clientDataJSON": b64(clientData), "signature": b64(signature), "userHandle": b64(userHandle)}})
					finish := func() *httptest.ResponseRecorder {
						form := url.Values{"code": {challenge.Code}, "data": {string(assertion)}}
						r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/webauthn_finish", strings.NewReader(form.Encode()))
						r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						r.AddCookie(cookie)
						w := httptest.NewRecorder()
						h.WebAuthnFinish(w, r)
						return w
					}
					result := finish()
					if proof != "valid" {
						if result.Code != http.StatusUnauthorized || result.Header().Get("Location") != "" || len(result.Result().Cookies()) != 0 {
							t.Fatalf("invalid proof authenticated: %d %s", result.Code, result.Body.String())
						}
						return
					}
					if result.Code != http.StatusSeeOther || result.Header().Get("Location") != want {
						t.Fatalf("finish=%d location=%q body=%s", result.Code, result.Header().Get("Location"), result.Body.String())
					}
					authenticated := false
					for _, c := range result.Result().Cookies() {
						session, err := h.browser.LoadSession(context.Background(), c.Value)
						if err == nil && session.Authenticated() {
							authenticated = true
							if session.Subject != subject || session.AuthenticationMethod != "mfa" {
								t.Fatalf("wrong authentication: %+v", session)
							}
						}
					}
					if !authenticated {
						t.Fatal("missing authenticated browser session")
					}
					replay := finish()
					if replay.Code != http.StatusForbidden && replay.Code != http.StatusUnauthorized {
						t.Fatalf("replay=%d", replay.Code)
					}
				})
			}
		}
	}
}

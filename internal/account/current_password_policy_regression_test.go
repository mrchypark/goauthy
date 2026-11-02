package account

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/rhiza"
)

func TestPutSelfPasswordAcceptsExistingPasswordAfterPolicyMaximumReduction(t *testing.T) {
	h, db, cookie, csrf := newPasswordIngressHandler(t)
	reduceCurrentPasswordPolicyMaximum(t, h, db)
	const current = "CurrentPassword1"
	const next = "NewPassword2"
	if err := h.rules.ValidatePassword([]byte(next)); err != nil {
		t.Fatalf("replacement does not fit reduced creation policy: %v", err)
	}
	response := passwordRequest(t, h, cookie, csrf, "subject-1", passwordChangeRequest{
		Current: stringPtr(current), Next: stringPtr("UpdatedPassword2"),
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("replacement above reduced maximum: status=%d body=%q want=400", response.Code, response.Body.String())
	}
	response = passwordRequest(t, h, cookie, csrf, "subject-1", passwordChangeRequest{
		Current: stringPtr(current), Next: stringPtr(next),
	})
	if response.Code != http.StatusOK {
		t.Fatalf("existing password rejected after maximum reduction: status=%d body=%q want=200", response.Code, response.Body.String())
	}
	if _, err := h.identity.Authenticate(t.Context(), "alice", []byte(current)); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("old password remains usable after change: %v", err)
	}
	if got, err := h.identity.Authenticate(t.Context(), "alice", []byte(next)); err != nil || got.Subject != "subject-1" {
		t.Fatalf("replacement authentication=%+v err=%v", got, err)
	}
}

func TestIssueModificationTokenAcceptsExistingPasswordAfterPolicyMaximumReduction(t *testing.T) {
	h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
	reduceCurrentPasswordPolicyMaximum(t, h, db)
	if got := tableCount(t, db, `SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject='subject-1'`); got != 0 {
		t.Fatalf("first-passkey fixture already has %d credentials", got)
	}
	response := httptest.NewRecorder()
	h.IssueModificationToken(response, sameOriginPasskeyRequest(t, http.MethodPost,
		"/auth/v1/users/subject-1/mfa_token", "subject-1", cookie, csrf,
		[]byte(`{"password":"CurrentPassword1"}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("existing password rejected for first-passkey modification token: status=%d body=%q want=200", response.Code, response.Body.String())
	}
	var proof struct {
		ID      string `json:"id"`
		Subject string `json:"user_id"`
		Expiry  int64  `json:"exp"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.ID == "" || proof.Subject != "subject-1" || proof.Expiry <= 0 {
		t.Fatalf("invalid modification token response: %+v", proof)
	}
	if got := tableCount(t, db, `SELECT COUNT(*) FROM identity_mfa_mod_tokens WHERE subject='subject-1' AND consumed_attempt IS NULL`); got != 1 {
		t.Fatalf("issued modification tokens=%d want=1", got)
	}
}

func reduceCurrentPasswordPolicyMaximum(t *testing.T, h *Handler, db *rhiza.DB) {
	t.Helper()
	// The fixture already persisted a valid 16-character credential. Rebuild
	// the identity policy too, as an operator restart with a lower limit would.
	h.rules.LengthMax = 12
	store, err := identity.NewStoreWithPolicies(db, testHasher(t), h.rules)
	if err != nil {
		t.Fatal(err)
	}
	h.identity = store
	if err := h.rules.ValidatePassword([]byte("CurrentPassword1")); err == nil {
		t.Fatal("existing password unexpectedly fits the reduced creation policy")
	}
	if got, err := h.identity.Authenticate(t.Context(), "alice", []byte("CurrentPassword1")); err != nil || got.Subject != "subject-1" {
		t.Fatalf("existing credential does not authenticate after policy reduction: auth=%+v err=%v", got, err)
	}
}

func TestCurrentPasswordAuthenticationIngressBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
		want  bool
	}{
		{name: "maximum Unicode credential", value: []byte(strings.Repeat("🔒", 256)), want: true},
		{name: "empty credential", value: nil},
		{name: "invalid UTF-8 credential", value: []byte{0xff}},
		{name: "over rune maximum", value: []byte(strings.Repeat("a", 257))},
		{name: "over Unicode rune and byte maxima", value: []byte(strings.Repeat("🔒", 257))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := boundedPassword(tc.value, maxPasswordLength); got != tc.want {
				t.Fatalf("authentication ingress accepted=%v want=%v bytes=%d", got, tc.want, len(tc.value))
			}
		})
	}
}

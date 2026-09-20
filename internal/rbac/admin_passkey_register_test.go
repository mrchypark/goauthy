package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/rhiza"
)

// TestAdminRegisterPasskeyFailsClosedWithoutEnrollmentBinding covers
// GA-ENROLL-ADMIN-001: administrator-initiated enrollment has no bounded
// continuation, so the mounted route must report that its contract does not
// exist and leave no enrollment state behind for the target account.
func TestAdminRegisterPasskeyFailsClosedWithoutEnrollmentBinding(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	h.SetPasskeyService(&passkey.Service{})
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/member/webauthn/admin_register", nil)
	request.SetPathValue("subject", "member")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	h.AdminRegisterPasskey(response, request)
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("admin register status=%d body=%q", response.Code, response.Body.String())
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM identity_webauthn_ceremonies`,
		`SELECT COUNT(*) FROM identity_webauthn_credentials WHERE subject='member'`,
	} {
		rows, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
			t.Fatalf("query %q rows=%v err=%v", query, rows.Rows, err)
		}
	}
}

package recovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDuplicatePendingOrphanResendsSetupWithoutChangingResponse(t *testing.T) {
	t.Parallel()
	service, sender := testService(t, "subject-review-orphan", "orphan-user")
	if err := WithOpenRegistration(RegistrationConfig{
		Enabled: true, AllowedDomains: []string{"example.test"}, RedirectValidator: ExactRedirectURIs(nil),
	}, time.Hour, func(context.Context, string) (bool, error) { return false, nil })(service); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) }
	service.pow.now = service.now

	register := func(email, ip string) *httptest.ResponseRecorder {
		t.Helper()
		challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
		if err != nil {
			t.Fatal(err)
		}
		body := `{"email":"` + email + `","given_name":"Test","pow":"` + solveProof(t, challenge) + `"}`
		return openRegistrationRequest(t, service, body, ip)
	}
	created := register("pending@example.test", "192.0.2.91:1234")
	if created.Code != http.StatusNoContent || len(sender.passwordNewMessages()) != 1 {
		t.Fatalf("initial registration status=%d messages=%#v", created.Code, sender.passwordNewMessages())
	}
	rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT subject FROM identity_users WHERE username='pending@example.test'`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("pending identity rows=%v err=%v", rows.Rows, err)
	}
	subject, ok := rows.Rows[0][0].(string)
	if !ok {
		t.Fatalf("pending subject has type %T", rows.Rows[0][0])
	}
	if _, err := storage.Execute(context.Background(), service.db, rhiza.ExecuteRequest{
		RequestID: "review-delete-only-password-new-proof",
		SQL:       `DELETE FROM identity_password_reset_tokens WHERE subject=? AND usage='password_new'`,
		Args:      []any{subject},
	}); err != nil {
		t.Fatal(err)
	}

	duplicate := register("pending@example.test", "192.0.2.92:1234")
	unknown := register("unknown@example.test", "192.0.2.93:1234")
	if duplicate.Code != unknown.Code || duplicate.Body.String() != unknown.Body.String() || duplicate.Code != http.StatusNoContent {
		t.Fatalf("registration responses reveal duplicate: duplicate=%d/%q unknown=%d/%q", duplicate.Code, duplicate.Body.String(), unknown.Code, unknown.Body.String())
	}
	if got := sender.passwordNewMessages(); len(got) != 3 || got[1].To != "pending@example.test" {
		t.Fatalf("setup reissue was not delivered for orphan: messages=%#v", got)
	}
	if got := sender.alreadyRegisteredRecipients(); len(got) != 0 {
		t.Fatalf("orphan duplicate used already-registered delivery: %v", got)
	}
	if strings.Contains(sender.passwordNewMessages()[1].ResetURL, " ") {
		t.Fatal("setup URL contains whitespace")
	}
}

func TestExpiredPendingSetupSurvivesOtherPasswordResetAndCleanup(t *testing.T) {
	t.Parallel()
	service, sender := testService(t, "subject-review-reset", "reset-user")
	if err := WithOpenRegistration(RegistrationConfig{
		Enabled: true, AllowedDomains: []string{"example.test"}, RedirectValidator: ExactRedirectURIs(nil),
	}, time.Minute, func(context.Context, string) (bool, error) { return false, nil })(service); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	service.now = func() time.Time { return now }
	service.pow.now = service.now
	register := func(email, ip string) *httptest.ResponseRecorder {
		t.Helper()
		challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
		if err != nil {
			t.Fatal(err)
		}
		body := `{"email":"` + email + `","given_name":"Test","pow":"` + solveProof(t, challenge) + `"}`
		return openRegistrationRequest(t, service, body, ip)
	}
	if response := register("expired-pending@example.test", "192.0.2.94:1234"); response.Code != http.StatusNoContent {
		t.Fatalf("initial registration status=%d body=%q", response.Code, response.Body.String())
	}
	rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT subject FROM identity_users WHERE username='expired-pending@example.test'`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("pending identity rows=%v err=%v", rows.Rows, err)
	}
	subject, ok := rows.Rows[0][0].(string)
	if !ok {
		t.Fatalf("pending subject has type %T", rows.Rows[0][0])
	}
	if _, err := storage.Execute(context.Background(), service.db, rhiza.ExecuteRequest{
		RequestID: "review-expire-password-new-proof",
		SQL:       `UPDATE identity_password_reset_tokens SET issued_at_unix_ms=?,expires_at_unix_ms=? WHERE subject=? AND usage='password_new'`,
		Args:      []any{now.Add(-2 * time.Minute).UnixMilli(), now.Add(-time.Minute).UnixMilli(), subject},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.identity.IssuePasswordReset(context.Background(), "subject-review-reset", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CleanupExpiredTokens(context.Background()); err != nil {
		t.Fatal(err)
	}
	if response := register("expired-pending@example.test", "192.0.2.95:1234"); response.Code != http.StatusNoContent {
		t.Fatalf("same-email setup reissue status=%d body=%q", response.Code, response.Body.String())
	}
	if got := sender.passwordNewMessages(); len(got) != 2 || got[1].To != "expired-pending@example.test" {
		t.Fatalf("same-email setup was not reissued: messages=%#v", got)
	}
}

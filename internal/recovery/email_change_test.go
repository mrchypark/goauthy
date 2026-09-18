package recovery

import (
	"context"
	"testing"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/rhiza"
)

func TestIssueForStaleEmailDoesNotDeliverAfterAdministratorUpdate(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	ctx := context.Background()
	if err := service.BindEmail(ctx, "subject-1", "old@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.identity.UpdateUserWithGuard(ctx, "subject-1", identity.UserUpdate{Email: "new@example.test", Enabled: true}, func() (string, []any) { return "1=1", nil }); err != nil {
		t.Fatal(err)
	}
	// The old lookup may already be queued in an in-flight HTTP request.
	if err := service.issueFor(ctx, "subject-1", "old@example.test"); err != nil {
		t.Fatal(err)
	}
	if len(sender.messages()) != 0 {
		t.Fatal("sent a fresh recovery proof to the former address")
	}
	rows, err := service.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_password_reset_tokens WHERE subject='subject-1'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("stale request issued token rows=%v err=%v", rows.Rows, err)
	}
	if err := service.IssueForSubject(ctx, "subject-1"); err != nil {
		t.Fatal(err)
	}
	if messages := sender.messages(); len(messages) != 1 || messages[0].To != "new@example.test" {
		t.Fatal("current destination did not receive recovery")
	}
}

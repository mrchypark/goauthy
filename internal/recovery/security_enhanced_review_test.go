package recovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCleanupExpiredTokensUsesResetScopeAndFreshCutoffMutation(t *testing.T) {
	t.Parallel()
	service, _ := testService(t, "subject-reset-cleanup", "reset-cleanup")
	ctx := context.Background()
	base := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	service.now = func() time.Time { return base }
	insert := func(requestID, digest, usage string, expires time.Time) {
		t.Helper()
		_, err := storage.Execute(ctx, service.db, rhiza.ExecuteRequest{RequestID: requestID,
			SQL:  `INSERT INTO identity_password_reset_tokens(token_digest,subject,password_generation,issued_at_unix_ms,expires_at_unix_ms,usage) VALUES(?,?,1,?,?,?)`,
			Args: []any{digest, "subject-reset-cleanup", base.Add(-time.Hour).UnixMilli(), expires.UnixMilli(), usage},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("review-reset-expired", strings.Repeat("a", 43), "password_reset", base.Add(-time.Second))
	insert("review-new-expired", strings.Repeat("b", 43), "password_new", base.Add(-time.Second))
	insert("review-reset-live", strings.Repeat("c", 43), "password_reset", base.Add(time.Hour))

	removed, err := service.CleanupExpiredTokens(ctx)
	if err != nil || removed != 1 {
		t.Fatalf("first cleanup removed=%d err=%v", removed, err)
	}
	if got := countResetCleanupRows(t, service, ""); got != 2 {
		t.Fatalf("cleanup should retain password_new and live reset rows, got %d", got)
	}

	insert("review-reset-expired-later", strings.Repeat("d", 43), "password_reset", base.Add(time.Second))
	service.now = func() time.Time { return base.Add(2 * time.Second) }
	removed, err = service.CleanupExpiredTokens(ctx)
	if err != nil || removed != 1 {
		t.Fatalf("later cleanup removed=%d err=%v", removed, err)
	}
	if got := countResetCleanupRows(t, service, "password_reset"); got != 1 {
		t.Fatalf("later cutoff left an expired reset token, remaining=%d", got)
	}
}

func countResetCleanupRows(t *testing.T, service *Service, usage string) int64 {
	t.Helper()
	sql := `SELECT COUNT(*) FROM identity_password_reset_tokens`
	var args []any
	if usage != "" {
		sql += ` WHERE usage=?`
		args = append(args, usage)
	}
	rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("count query rows=%v err=%v", rows.Rows, err)
	}
	count, ok := rows.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("unexpected count value %T", rows.Rows[0][0])
	}
	return count
}

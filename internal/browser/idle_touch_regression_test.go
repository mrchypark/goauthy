package browser

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func TestSessionActivityBeforeTenSecondIdleBoundaryKeepsSessionLive(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	const idleTimeout = 10 * time.Second
	store.idleTimeout = idleTimeout
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	lastSeen := now.UnixMilli()
	for second := 1; second <= 10; second++ {
		now = now.Add(time.Second)
		loaded, err := store.LoadSession(ctx, issued.Token)
		if err != nil {
			t.Fatalf("activity at second %d lost the session: %v", second, err)
		}
		rows, err := store.db.Query(ctx, rhiza.QueryRequest{
			SQL:  `SELECT last_seen_at_unix_ms FROM browser_sessions WHERE token_digest=?`,
			Args: []any{issued.ID}, Consistency: rhiza.ConsistencyLinearizable,
		})
		if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
			t.Fatalf("touch row at second %d: rows=%v err=%v", second, rows.Rows, err)
		}
		persisted, ok := rows.Rows[0][0].(int64)
		if !ok || persisted != loaded.lastSeenAt.UnixMilli() {
			t.Fatalf("touch at second %d differs between SQL and returned session: db=%v session=%s", second, rows.Rows[0][0], loaded.lastSeenAt)
		}
		if persisted < lastSeen {
			t.Fatalf("last-seen moved backward at second %d: got=%d want at least %d", second, persisted, lastSeen)
		}
		lastSeen = persisted
	}
	if lastSeen == issued.CreatedAt.UnixMilli() || now.Sub(time.UnixMilli(lastSeen)) >= idleTimeout {
		t.Fatalf("one-second activity did not refresh persisted idle time: last_seen=%s now=%s", time.UnixMilli(lastSeen), now)
	}

	if err := store.RevokeSession(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSession(ctx, issued.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("session touch boundary bypassed revocation: %v", err)
	}
}

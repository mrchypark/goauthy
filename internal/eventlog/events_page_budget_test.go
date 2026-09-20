package eventlog_test

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// eventBudgetSeedSQL writes one event per millisecond below the base instant,
// newest id first, with the id carrying the row index like the other page seeds.
// Every column is filled with a value at its widest: an address of the longest
// accepted form, the smallest int64, both 43-character hashes and the maximum
// 4,096-byte text, so one page of these rows is the worst case the budget covers.
const eventBudgetSeedSQL = `WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?)
INSERT INTO event_log(id,timestamp,level,typ,ip,data,text,prev_hash,integrity_hash)
SELECT substr(printf('%042d',x),1,42)||'A', ?-x, 0, 'RauthyHealthy', ?, ?, ?, ?, ? FROM n`

// TestListGuardedEncodedPageBudget covers GA66-EVENTS-001: Rhiza also checks the
// JSON encoding of a query result against 16 MiB, and its encoder spends six
// bytes on one "<", so a page sized from the raw 4,096-byte text limit turns
// valid records into HTTP 503. Every accepted limit must instead return a page
// plus its continuation through the whole retained result, with the look-ahead
// row and every column inside the encoded budget.
func TestListGuardedEncodedPageBudget(t *testing.T) {
	const seeded = 1500
	ctx := context.Background()
	base := time.UnixMilli(eventPageBaseMilli)
	db, store, now := cleanupFixture(t)
	text := strings.Repeat("<", 4096)
	hash := strings.Repeat("A", 43)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "event-budget-seed",
		SQL:       eventBudgetSeedSQL,
		Args:      []any{seeded, base.UnixMilli(), "0000:0000:0000:0000:0000:ffff:255.255.255.255", int64(math.MinInt64), text, hash, hash},
	}); err != nil {
		t.Fatal(err)
	}
	if count := eventCount(t, db); count != seeded {
		t.Fatalf("seeded events=%d", count)
	}
	query := eventlog.Query{From: base.Add(-time.Hour).Unix(), Level: eventlog.Info}

	seen := make(map[string]bool, seeded)
	var cursor *eventlog.Cursor
	pages := 0
	for {
		rows, next, authorized, err := store.ListGuarded(ctx, query, now, cursor, eventlog.MaxPageSize, "1=1")
		if err != nil {
			t.Fatalf("page %d at the maximum accepted limit: %v", pages+1, err)
		}
		if !authorized {
			t.Fatalf("page %d is not authorized", pages+1)
		}
		pages++
		if pages > seeded/eventlog.MaxPageSize+2 {
			t.Fatal("pagination did not terminate")
		}
		if len(rows) == 0 {
			t.Fatalf("page %d returned no rows before the continuation ended", pages)
		}
		for _, row := range rows {
			if seen[row.ID] || row.Text == nil || *row.Text != text {
				t.Fatalf("page %d repeated an event or lost its maximum-length text: %s", pages, row.ID)
			}
			seen[row.ID] = true
		}
		if next == nil {
			break
		}
		if len(rows) != eventlog.MaxPageSize {
			t.Fatalf("page %d returned %d rows with a continuation, want a full page", pages, len(rows))
		}
		cursor = next
	}
	if len(seen) != seeded {
		t.Fatalf("pagination reached %d of %d events", len(seen), seeded)
	}
	if pages < 2 {
		t.Fatalf("maximum-length texts fit in %d pages, the seed needs pagination", pages)
	}
}

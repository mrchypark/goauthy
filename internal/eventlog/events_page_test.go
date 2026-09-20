package eventlog_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// Seed one second that cannot fit a single query, with the row index encoded in
// the event id so a reader can check every returned row against its source:
//
//   - x = 1:           base + 5s, 8-byte text
//   - x = 2..901:      base, 8-byte text
//   - x = 902..1201:   base, maximum-length 4096-byte text (the 1,200 events
//     from x = 2 share one millisecond, newest id first)
//   - x = 1202..10000: one millisecond older each row, 8-byte text
//
// The id is 42 zero-padded decimal digits plus "A": canonical base64url of 32
// bytes, unique per row, and its last five digits are the row index.
const eventPageSeedSQL = `WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000)
INSERT INTO event_log(id,timestamp,level,typ,text)
SELECT substr(printf('%042d',x),1,42)||'A',
       CASE WHEN x=1 THEN ? WHEN x<=1201 THEN ? ELSE ?-(x-1201) END,
       0,
       'RauthyHealthy',
	       substr(replace(hex(zeroblob(2048)),'0','x'),1,CASE WHEN x BETWEEN 902 AND 1201 THEN 4096 ELSE 8 END)
FROM n`

const eventPageBaseMilli = 1_800_000_000_000

// TestListGuardedBoundedPages covers GA-EVENTS-001: 10,000 events plus the
// authorization marker exceed the 10,000-row Rhiza result budget, and maximum-
// length texts reach the 16 MiB byte budget long before that, so an unbounded
// query becomes HTTP 503 exactly when the history matters. Every page must
// instead stay bounded, report continuation, split equal timestamps by id, reach
// every event once, and re-check authorization in its own snapshot.
func TestListGuardedBoundedPages(t *testing.T) {
	ctx := context.Background()
	base := time.UnixMilli(eventPageBaseMilli)
	db, store, now := cleanupFixture(t)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "event-page-seed",
		SQL:       eventPageSeedSQL,
		Args:      []any{base.Add(5 * time.Second).UnixMilli(), base.UnixMilli(), base.UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}
	if seeded := eventCount(t, db); seeded != 10_000 {
		t.Fatalf("seeded events=%d", seeded)
	}
	query := eventlog.Query{From: base.Add(-time.Hour).Unix(), Level: eventlog.Info}

	// No caller can ask for a page that alone would cross the row budget, and the
	// bounded page is what keeps maximum-length texts inside the byte budget.
	if _, _, _, err := store.ListGuarded(ctx, query, now, nil, eventlog.MaxPageSize+1, "1=1"); err == nil {
		t.Fatal("page above the result budget was accepted")
	}

	// The 9,999-event range just below the failure threshold is served the same
	// way as the full range, whose whole result no longer fits one query.
	below := query
	belowUntil := base.Unix()
	below.Until = &belowUntil
	body, next, authorized, err := store.ListGuarded(ctx, below, now, nil, eventlog.MaxPageSize, "1=1")
	if err != nil || !authorized || len(body) != eventlog.MaxPageSize || next == nil {
		t.Fatalf("9,999-event page rows=%d next=%#v authorized=%v err=%v", len(body), next, authorized, err)
	}
	boundary := body[len(body)-1]
	resumed, err := eventlog.ParseCursor(next.Token())
	if err != nil || *resumed != *next {
		t.Fatalf("continuation token round trip=%#v err=%v", resumed, err)
	}
	for _, invalid := range []string{"", "e1", "e1." + strconv.FormatInt(boundary.Timestamp, 10) + ".short", "e1.01." + boundary.ID, "e1.-1." + boundary.ID, next.Token() + "x"} {
		if _, err := eventlog.ParseCursor(invalid); err == nil {
			t.Fatalf("non-canonical continuation token %q accepted", invalid)
		}
	}

	// A full page keeps the maximum-length texts of its own newest events.
	full, next, authorized, err := store.ListGuarded(ctx, query, now, nil, eventlog.MaxPageSize, "1=1")
	if err != nil || !authorized || len(full) != eventlog.MaxPageSize || next == nil {
		t.Fatalf("full page rows=%d next=%#v authorized=%v err=%v", len(full), next, authorized, err)
	}
	if full[0].Timestamp != base.Add(5*time.Second).UnixMilli() {
		t.Fatalf("first page did not start at the newest event: %d", full[0].Timestamp)
	}
	large := 0
	for i, row := range full {
		_, textLen, ok := eventPageRow(row, base)
		if !ok {
			t.Fatalf("page row %d does not match its seeded event: %#v", i, row)
		}
		if textLen == 4096 {
			large++
		}
	}
	if large != 300 {
		t.Fatalf("first page carried %d maximum-length texts, want 300", large)
	}
	last := full[len(full)-1]
	if next.Timestamp != last.Timestamp || next.ID != last.ID {
		t.Fatalf("continuation %#v does not resume after %#v", next, last)
	}

	// Traversal reaches every retained event exactly once and terminates, and a
	// page boundary inside the equal-timestamp run is resumed by id.
	seen := make(map[string]bool, 10_000)
	for _, row := range full {
		seen[row.ID] = true
	}
	tieSplit, repeatedLarge := false, 0
	for cursor, pages := next, 1; cursor != nil; pages++ {
		if pages > 30 {
			t.Fatal("pagination did not terminate")
		}
		rows, following, ok, err := store.ListGuarded(ctx, query, now, cursor, 500, "1=1")
		if err != nil || !ok {
			t.Fatalf("page %d authorized=%v err=%v", pages, ok, err)
		}
		if len(rows) == 0 {
			t.Fatalf("page %d returned no rows before the continuation ended", pages)
		}
		if rows[0].Timestamp == last.Timestamp {
			tieSplit = true
		}
		for _, row := range rows {
			if seen[row.ID] {
				t.Fatalf("event %s returned by two pages", row.ID)
			}
			_, textLen, ok := eventPageRow(row, base)
			if !ok {
				t.Fatalf("event %s does not match its seeded event: %#v", row.ID, row)
			}
			if textLen == 4096 {
				repeatedLarge++
			}
			seen[row.ID] = true
		}
		last, cursor = rows[len(rows)-1], following
	}
	if len(seen) != 10_000 {
		t.Fatalf("traversal reached %d of 10,000 events", len(seen))
	}
	if !tieSplit {
		t.Fatal("no page boundary fell inside the equal-timestamp run")
	}
	if repeatedLarge != 0 {
		t.Fatalf("%d maximum-length texts were returned after the first page", repeatedLarge)
	}

	// A cursor must not become an authorization cache: a denied caller gets the
	// marker of the same snapshot and no continuation.
	rows, following, authorized, err := store.ListGuarded(ctx, query, now, next, 500, "0=1")
	if err != nil || authorized || following != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("revoked page rows=%#v next=%#v authorized=%v err=%v", rows, following, authorized, err)
	}
}

// eventPageRow returns the seeded row index and text length of one returned
// event, reporting false when the row does not match what the seed wrote for
// that index: the id carries the index, the tie run shares the base millisecond,
// and only x = 902..1201 carry a maximum-length text.
func eventPageRow(row eventlog.Event, base time.Time) (int, int, bool) {
	if len(row.ID) != 43 || !strings.HasSuffix(row.ID, "A") {
		return 0, 0, false
	}
	index, err := strconv.Atoi(row.ID[37:42])
	if err != nil || index < 1 || index > 10_000 || row.Text == nil || row.Type != eventlog.RauthyHealthy || row.Level != eventlog.Info {
		return 0, 0, false
	}
	wantTimestamp := base.UnixMilli()
	switch {
	case index == 1:
		wantTimestamp = base.Add(5 * time.Second).UnixMilli()
	case index > 1201:
		wantTimestamp = base.Add(-time.Duration(index-1201) * time.Millisecond).UnixMilli()
	}
	if row.Timestamp != wantTimestamp {
		return 0, 0, false
	}
	want := 8
	if index >= 902 && index <= 1201 {
		want = 4096
	}
	if len(*row.Text) != want {
		return 0, 0, false
	}
	return index, want, true
}

package loginpolicy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAutomaticBlacklistDefaultCapacity(t *testing.T) {
	if ipblacklist.DefaultMaxEntries != 10000 {
		t.Fatalf("documented default=%d", ipblacklist.DefaultMaxEntries)
	}
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 0)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.UnixMilli(1800000000000).UTC()
	created := now.Add(-time.Second).UnixMilli()
	threshold := now.Add(time.Second)
	const permanent = "192.0.2.11/32"
	const victim = "192.0.2.12/32"
	const note = "retained manual note"
	prefixes := []string{permanent, victim}
	for len(prefixes) < 10000 {
		n := len(prefixes)
		prefixes = append(prefixes, fmt.Sprintf("10.%d.%d.0/24", n/256, n%256))
	}
	seen := map[string]bool{}
	for _, p := range prefixes {
		canonical, err := ipblacklist.CanonicalPrefix(p)
		if err != nil || canonical.String() != p || seen[p] {
			t.Fatalf("invalid/duplicate seed %s", p)
		}
		seen[p] = true
	}
	// Fixture-only inserts. Production Failure below owns counter/prune/upsert/event admission.
	for start := 0; start < len(prefixes); start += 500 {
		end := min(start+500, len(prefixes))
		args := make([]any, 0, end-start+5)
		for _, p := range prefixes[start:end] {
			args = append(args, p)
		}
		args = append(args, note, victim, threshold.UnixMilli(), created, created)
		sql := `WITH seed(prefix) AS (VALUES ` + strings.TrimSuffix(strings.Repeat("(?),", end-start), ",") + `) INSERT INTO ip_blacklist_entries(prefix,note,expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms) SELECT prefix,?,CASE WHEN prefix=? THEN ? ELSE NULL END,?,? FROM seed`
		req := rhiza.ExecuteRequest{RequestID: fmt.Sprintf("auto-cap-seed-%d", start), SQL: sql, Args: args}
		encoded, err := json.Marshal(req)
		if err != nil || len(args) > 999 || len(sql) > 256<<10 || len(encoded) > 64<<10 {
			t.Fatalf("seed bounds args=%d sql=%d request=%d err=%v", len(args), len(sql), len(encoded), err)
		}
		if _, err = storage.Execute(t.Context(), db, req); err != nil {
			t.Fatal(err)
		}
	}
	count := func() {
		t.Helper()
		n, err := blacklist.Count(t.Context())
		if err != nil || n != 10000 {
			t.Fatalf("blacklist count=%d err=%v", n, err)
		}
	}
	query := func(sql string, args ...any) [][]any {
		t.Helper()
		r, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		return r.Rows
	}
	events := func(typ, ip string) int64 {
		t.Helper()
		return autoEventScalar(t, db, `SELECT COUNT(*) FROM event_log WHERE typ=? AND ip=?`, typ, ip).(int64)
	}
	seventh := func(ip string, at time.Time) {
		t.Helper()
		status, err := store.Failure(t.Context(), ip, at)
		if err != nil || status.Failures != 7 || !status.BlockedUntil.Equal(at.Add(time.Minute)) {
			t.Fatalf("seventh %s status=%+v err=%v", ip, status, err)
		}
		want := [][]any{{int64(7), at.Add(time.Minute).UnixMilli(), at.UnixMilli()}}
		if got := query(`SELECT failures,blocked_until_unix_ms,updated_at_unix_ms FROM login_ip_failures WHERE key_digest=?`, digest(ip)); !reflect.DeepEqual(got, want) {
			t.Fatalf("seventh failure row=%v want=%v", got, want)
		}
	}
	count()
	const fullIP = "192.0.2.20"
	seedSixFailures(t, store, now, fullIP)
	seventh(fullIP, now)
	count()
	if _, err := blacklist.Get(t.Context(), fullIP+"/32"); err != ipblacklist.ErrNotFound {
		t.Fatalf("full-capacity admission should be absent: %v", err)
	}
	if events("InvalidLogins", fullIP) != 7 || events("IpBlacklisted", fullIP) != 0 {
		t.Fatal("full-capacity event accounting")
	}
	later := now.Add(time.Millisecond)
	seedSixFailures(t, store, later, "192.0.2.11")
	seventh("192.0.2.11", later)
	entry, err := blacklist.Get(t.Context(), permanent)
	wantPermanent := ipblacklist.Entry{Prefix: permanent, Note: note, CreatedAtUnixMs: created, UpdatedAtUnixMs: later.UnixMilli()}
	if err != nil || !reflect.DeepEqual(entry, wantPermanent) {
		t.Fatalf("existing-prefix exception failed: entry=%+v err=%v", entry, err)
	}
	count()
	if events("InvalidLogins", "192.0.2.11") != 7 || events("IpBlacklisted", "192.0.2.11") != 0 {
		t.Fatal("permanent-prefix event accounting")
	}
	const target = "192.0.2.30"
	seedSixFailures(t, store, now.Add(2*time.Millisecond), target)
	beforeFailure := query(`SELECT key_digest,failures,blocked_until_unix_ms,updated_at_unix_ms FROM login_ip_failures WHERE key_digest=?`, digest(target))
	beforeVictim, err := blacklist.Get(t.Context(), victim)
	if err != nil {
		t.Fatal(err)
	}
	beforeEvents := query(`SELECT typ,COUNT(*) FROM event_log GROUP BY typ ORDER BY typ`)
	beforeOrder := autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	execAutoEventTestSQL(t, db, "cap-abort-create", `CREATE TRIGGER capacity_event_abort BEFORE INSERT ON event_log WHEN NEW.typ='IpBlacklisted' BEGIN SELECT RAISE(ABORT, 'capacity event sink unavailable'); END`)
	t.Cleanup(func() {
		execAutoEventTestSQL(t, db, "cap-abort-cleanup", `DROP TRIGGER IF EXISTS capacity_event_abort`)
	})
	if _, err := store.Failure(t.Context(), target, threshold); err == nil {
		t.Fatal("late event abort succeeded")
	}
	if got := query(`SELECT key_digest,failures,blocked_until_unix_ms,updated_at_unix_ms FROM login_ip_failures WHERE key_digest=?`, digest(target)); !reflect.DeepEqual(got, beforeFailure) {
		t.Fatalf("failure row not rolled back: %v", got)
	}
	afterVictim, err := blacklist.Get(t.Context(), victim)
	if err != nil || !reflect.DeepEqual(afterVictim, beforeVictim) {
		t.Fatalf("victim not rolled back: %v", err)
	}
	count()
	if _, err := blacklist.Get(t.Context(), target+"/32"); err != ipblacklist.ErrNotFound {
		t.Fatalf("target not rolled back: %v", err)
	}
	if !reflect.DeepEqual(query(`SELECT typ,COUNT(*) FROM event_log GROUP BY typ ORDER BY typ`), beforeEvents) || autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`) != (beforeOrder) {
		t.Fatal("events not rolled back")
	}
	if events("InvalidLogins", target) != 6 || events("IpBlacklisted", target) != 0 {
		t.Fatal("target rollback events")
	}
	execAutoEventTestSQL(t, db, "cap-abort-drop", `DROP TRIGGER capacity_event_abort`)
	seventh(target, threshold)
	count()
	if _, err := blacklist.Get(t.Context(), victim); err != ipblacklist.ErrNotFound {
		t.Fatalf("expiry-equality victim retained: %v", err)
	}
	expires := threshold.Add(time.Minute).UnixMilli()
	wantTarget := ipblacklist.Entry{Prefix: target + "/32", ExpiresAtUnixMs: &expires, CreatedAtUnixMs: threshold.UnixMilli(), UpdatedAtUnixMs: threshold.UnixMilli()}
	entry, err = blacklist.Get(t.Context(), target+"/32")
	if err != nil || !reflect.DeepEqual(entry, wantTarget) {
		t.Fatalf("target fields=%+v err=%v", entry, err)
	}
	if events("InvalidLogins", target) != 7 || events("IpBlacklisted", target) != 1 {
		t.Fatal("successful threshold event accounting")
	}
	wantEvent := [][]any{{threshold.UnixMilli(), int64(2), target, threshold.Add(time.Minute).Unix(), nil}}
	if got := query(`SELECT timestamp,level,ip,data,text FROM event_log WHERE typ='IpBlacklisted' AND ip=?`, target); !reflect.DeepEqual(got, wantEvent) {
		t.Fatalf("blacklist event=%v want=%v", got, wantEvent)
	}
	if autoEventScalar(t, db, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`) != beforeOrder+2 {
		t.Fatal("expected exactly two event order increments")
	}
}

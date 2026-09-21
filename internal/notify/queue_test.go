package notify

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func queueFixture(t *testing.T) (*rhiza.DB, context.Context, time.Time) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "notify-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db, ctx, time.UnixMilli(2_000_000_000_000).UTC()
}
func putEvent(t *testing.T, db *rhiza.DB, e eventlog.Event) {
	s, err := e.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "seed-" + e.ID, Statements: []rhiza.SQLStatement{s}}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationQueueSnapshotLeaseRetryAndRestart(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://hooks.one.test/a")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Info}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	e := eventlog.TestEvent("queue-event", "", now)
	putEvent(t, db, e)
	one, err := q.Claim(ctx, id, now, 1, time.Minute)
	if err != nil || len(one) != 1 {
		t.Fatalf("claim=%#v err=%v", one, err)
	}
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "delete-source", SQL: `DELETE FROM event_log WHERE id=?`, Args: []any{e.ID}}); err != nil {
		t.Fatal(err)
	}
	q2 := &RhizaQueue{DB: db, allowed: map[string]bool{id: true}}
	if got, err := q2.Claim(ctx, id, now, 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("lease claim=%#v err=%v", got, err)
	}
	if err := q2.Ack(ctx, id, e.ID, one[0].Lease, now); err != nil {
		t.Fatal(err)
	}
	if got, err := q2.Claim(ctx, id, now.Add(2*time.Minute), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("acked reclaim=%#v err=%v", got, err)
	}

	e2 := eventlog.TestEvent("queue-event-2", "", now)
	putEvent(t, db, e2)
	d, err := q2.Claim(ctx, id, now.Add(3*time.Minute), 1, time.Minute)
	if err != nil || len(d) != 1 {
		t.Fatalf("second claim=%#v err=%v", d, err)
	}
	if err := q2.Fail(ctx, id, e2.ID, d[0].Lease, now.Add(3*time.Minute), time.Second, "ignored"); err != nil {
		t.Fatal(err)
	}
	if got, err := q2.Claim(ctx, id, now.Add(3*time.Minute), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("early retry=%#v err=%v", got, err)
	}
	if got, err := q2.Claim(ctx, id, now.Add(3*time.Minute+time.Second), 1, time.Minute); err != nil || len(got) != 1 {
		t.Fatalf("boundary retry=%#v err=%v", got, err)
	}
}

func TestNotificationDestinationDoesNotBackfill(t *testing.T) {
	db, ctx, now := queueFixture(t)
	old := Identity("slack", "https://hooks.old.test/a")
	newID := Identity("slack", "https://hooks.new.test/a")
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: old, Kind: "slack", Level: eventlog.Info}}, 1); err != nil {
		t.Fatal(err)
	}
	putEvent(t, db, eventlog.TestEvent("old", "", now))
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: newID, Kind: "slack", Level: eventlog.Info}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.Claim(ctx, newID, now, 10, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("backfill=%#v err=%v", got, err)
	}
	putEvent(t, db, eventlog.TestEvent("new", "", now.Add(time.Second)))
	got, err := q.Claim(ctx, newID, now.Add(time.Second), 10, time.Minute)
	if err != nil || len(got) != 1 {
		t.Fatalf("new=%#v err=%v", got, err)
	}
	ts, err := q.Targets(ctx)
	if err != nil || len(ts) != 1 || ts[0].Name != newID {
		t.Fatalf("targets=%#v err=%v", ts, err)
	}
}

func TestNotificationQueueConcurrentClaimReclaimAndColdRestart(t *testing.T) {
	ctx := t.Context()
	config := rhiza.Config{NodeID: "notify-restart", DataDir: t.TempDir()}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(2_000_000_000_000).UTC()
	id := Identity("slack", "https://hooks.example.test/restart")
	targets := []Target{{Name: id, Kind: "slack", Level: eventlog.Info}}
	q, err := NewRhizaQueue(ctx, db, targets, 1)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := NewRhizaQueue(ctx, db, targets, 1)
	if err != nil {
		t.Fatal(err)
	}
	event := eventlog.TestEvent("cold-restart", "", now)
	putEvent(t, db, event)
	type result struct {
		deliveries []Delivery
		err        error
	}
	start, done := make(chan struct{}), make(chan result, 2)
	for _, queue := range []*RhizaQueue{q, q2} {
		go func() {
			<-start
			d, err := queue.Claim(ctx, id, now, 1, time.Minute)
			done <- result{d, err}
		}()
	}
	close(start)
	var claimed []Delivery
	for range 2 {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		claimed = append(claimed, r.deliveries...)
	}
	if len(claimed) != 1 {
		t.Fatalf("concurrent claims=%d, want one", len(claimed))
	}
	oldLease := claimed[0].Lease
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "notify-delete-source-restart", SQL: `DELETE FROM event_log WHERE id=?`, Args: []any{event.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRhizaQueue(ctx, db, targets, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Claim(ctx, id, now.Add(30*time.Second), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("restart lost live lease: %v %v", got, err)
	}
	reclaimed, err := restarted.Claim(ctx, id, now.Add(61*time.Second), 1, time.Minute)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim=%v err=%v", reclaimed, err)
	}
	if reclaimed[0].Event.ID != event.ID || reclaimed[0].Event.Text == nil || *reclaimed[0].Event.Text != *event.Text || reclaimed[0].Lease == oldLease {
		t.Fatal("retention/restart lost payload or lease ownership")
	}
	if err := restarted.Ack(ctx, id, event.ID, oldLease, now.Add(62*time.Second)); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT delivered_at_unix_ms,lease_token FROM event_notification_deliveries WHERE target=? AND event_id=?`, Args: []any{id, event.ID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != nil || row.Rows[0][1] != reclaimed[0].Lease {
		t.Fatalf("stale acknowledgement changed new lease: %#v err=%v", row, err)
	}
	if err := restarted.Ack(ctx, id, event.ID, reclaimed[0].Lease, now.Add(63*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Claim(ctx, id, now.Add(10*time.Minute), 1, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("acknowledged delivery retried: %v %v", got, err)
	}
}

func execRaw(t *testing.T, ctx context.Context, db *rhiza.DB, sql string, args ...any) {
	t.Helper()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "raw/" + rand.Text(), SQL: sql, Args: args}); err != nil {
		t.Fatal(err)
	}
}

func deliveryIDs(t *testing.T, ctx context.Context, db *rhiza.DB, target string) []string {
	t.Helper()
	r, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT event_id FROM event_notification_deliveries WHERE target=?", Args: []any{target}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(r.Rows))
	for _, row := range r.Rows {
		id, ok := row[0].(string)
		if !ok {
			t.Fatalf("invalid delivery id %T", row[0])
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func targetEnabled(t *testing.T, ctx context.Context, db *rhiza.DB, target string) int64 {
	t.Helper()
	return targetColumn(t, ctx, db, target, "enabled")
}

func targetColumn(t *testing.T, ctx context.Context, db *rhiza.DB, target, column string) int64 {
	t.Helper()
	r, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT " + column + " FROM event_notification_targets WHERE target=?", Args: []any{target}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("target %q %s inspection=%v err=%v", target, column, r.Rows, err)
	}
	value, ok := r.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("invalid %s value %T", column, r.Rows[0][0])
	}
	return value
}

// seedCleanupBacklog inserts eligible delivery snapshots using as few
// replicated mutations as the store's per-statement argument limit allows.
func seedCleanupBacklog(t *testing.T, ctx context.Context, db *rhiza.DB, target string, at time.Time, rows int) {
	t.Helper()
	const perStatement = 999 / 6
	statements := make([]rhiza.SQLStatement, 0, (rows+perStatement-1)/perStatement)
	for start := 0; start < rows; start += perStatement {
		count := min(perStatement, rows-start)
		sql := strings.Builder{}
		sql.WriteString("INSERT INTO event_notification_deliveries(target,event_id,timestamp,level,typ,next_attempt_at_unix_ms) VALUES")
		args := make([]any, 0, count*6)
		for i := range count {
			if i > 0 {
				sql.WriteString(",")
			}
			sql.WriteString("(?,?,?,?,?,?)")
			args = append(args, target, fmt.Sprintf("backlog-%06d", start+i), at.UnixMilli(), int64(eventlog.Info.Rank()), string(eventlog.NewUserRegistered), at.UnixMilli())
		}
		statements = append(statements, rhiza.SQLStatement{SQL: sql.String(), Args: args})
	}
	// One command per statement: a backlog large enough to exercise the
	// maintenance budget exceeds the engine's encoded-command limit otherwise.
	for _, statement := range statements {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "seed-backlog/" + rand.Text(), Statements: []rhiza.SQLStatement{statement}}); err != nil {
			t.Fatal(err)
		}
	}
}

func deliveryCount(t *testing.T, ctx context.Context, db *rhiza.DB, target string) int {
	t.Helper()
	r, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM event_notification_deliveries WHERE target=?", Args: []any{target}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("delivery count for %q=%v err=%v", target, r.Rows, err)
	}
	n, ok := r.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("invalid delivery count %T", r.Rows[0][0])
	}
	return int(n)
}

// TestNotificationCleanupReleasesExpiredAbandonedLease covers GA66-NOTIFY-001: a
// lease whose worker died must stop protecting its payload once the lease expires
// and the payload ages out, while an otherwise identical live lease is kept.
func TestNotificationCleanupReleasesExpiredAbandonedLease(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://abandoned-lease.example.test")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Warning}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	abandoned := eventlog.IPBlacklisted("lease-abandoned", "192.0.2.1", 0, now)
	putEvent(t, db, abandoned)
	lost, err := q.Claim(ctx, id, now, 1, time.Minute)
	if err != nil || len(lost) != 1 || lost[0].Event.ID != abandoned.ID {
		t.Fatalf("abandoned claim=%v err=%v", lost, err)
	}
	// The second delivery is identical apart from a worker that is still holding
	// its lease, so only the abandoned lease may be released.
	held := eventlog.IPBlacklisted("lease-held", "192.0.2.2", 0, now)
	putEvent(t, db, held)
	live, err := q.Claim(ctx, id, now, 1, 4*time.Hour)
	if err != nil || len(live) != 1 || live[0].Event.ID != held.ID {
		t.Fatalf("live claim=%v err=%v", live, err)
	}
	// Raising the threshold above the stranded event leaves it owed to nobody.
	q2, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Critical}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(2 * time.Hour) // past the abandoned lease and past retention
	removed, err := q2.Cleanup(ctx, at, time.Hour)
	if err != nil || removed != 1 {
		t.Fatalf("cleanup removed=%d err=%v, want only the abandoned lease", removed, err)
	}
	if got := deliveryIDs(t, ctx, db, id); !slices.Equal(got, []string{held.ID}) {
		t.Fatalf("retained=%v want only the live lease %q", got, held.ID)
	}
}

// TestNotificationEligibleDeliveryNotBlockedByIneligibleRows covers
// GA-NOTIFY-001: a below-threshold backlog must not delay a security event, and
// below-threshold events must not be queued in the first place.
func TestNotificationEligibleDeliveryNotBlockedByIneligibleRows(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://filter.example.test")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Warning}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy row queued before enqueue-time filtering existed, with the oldest
	// timestamp so it stays the first candidate a claim would pick.
	execRaw(t, ctx, db, "INSERT INTO event_notification_deliveries(target,event_id,timestamp,level,typ,next_attempt_at_unix_ms) VALUES(?,?,?,?,?,?)",
		id, "legacy-info", now.UnixMilli(), int64(eventlog.Info.Rank()), string(eventlog.NewUserRegistered), now.UnixMilli())
	for i := range 20 {
		putEvent(t, db, eventlog.Creation(fmt.Sprintf("info-%d", i), "user@example.test", "", false, now))
	}
	if got := deliveryIDs(t, ctx, db, id); !slices.Equal(got, []string{"legacy-info"}) {
		t.Fatalf("informational events queued %v, want only the legacy row", got)
	}
	warning := eventlog.IPBlacklisted("warning", "192.0.2.1", 0, now.Add(time.Second))
	putEvent(t, db, warning)
	got, err := q.Claim(ctx, id, now.Add(2*time.Second), 1, time.Minute)
	if err != nil || len(got) != 1 || got[0].Event.ID != warning.ID {
		t.Fatalf("claim=%v err=%v, want the warning event", got, err)
	}
}

// TestNotificationCleanupBoundsSnapshots covers GA-NOTIFY-002: snapshots need a
// bounded retention path that still keeps payloads owed to a destination.
func TestNotificationCleanupBoundsSnapshots(t *testing.T) {
	db, ctx, now := queueFixture(t)
	id := Identity("slack", "https://cleanup.example.test")
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: id, Kind: "slack", Level: eventlog.Warning}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	at := now.Add(2 * time.Hour)

	aged := eventlog.TestEvent("cleanup-aged", "", now)
	putEvent(t, db, aged)
	claimed, err := q.Claim(ctx, id, now, 1, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].Event.ID != aged.ID {
		t.Fatalf("aged claim=%v err=%v", claimed, err)
	}
	if err := q.Ack(ctx, id, aged.ID, claimed[0].Lease, now); err != nil {
		t.Fatal(err)
	}
	recent := eventlog.TestEvent("cleanup-recent", "", at)
	putEvent(t, db, recent)
	claimed, err = q.Claim(ctx, id, at, 1, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].Event.ID != recent.ID {
		t.Fatalf("recent claim=%v err=%v", claimed, err)
	}
	if err := q.Ack(ctx, id, recent.ID, claimed[0].Lease, at); err != nil {
		t.Fatal(err)
	}
	held := eventlog.TestEvent("cleanup-held", "", now)
	putEvent(t, db, held)
	claimed, err = q.Claim(ctx, id, now, 1, 2*time.Hour)
	if err != nil || len(claimed) != 1 || claimed[0].Event.ID != held.ID {
		t.Fatalf("held claim=%v err=%v", claimed, err)
	}
	agedPending := eventlog.TestEvent("cleanup-aged-pending", "", now)
	putEvent(t, db, agedPending)
	pending := eventlog.TestEvent("cleanup-pending", "", at)
	putEvent(t, db, pending)
	// Source-event expiration must not strand the snapshot still owed to the
	// destination.
	execRaw(t, ctx, db, "DELETE FROM event_log WHERE id=?", pending.ID)
	putEvent(t, db, eventlog.Creation("cleanup-info", "user@example.test", "", false, at))
	execRaw(t, ctx, db, "INSERT INTO event_notification_deliveries(target,event_id,timestamp,level,typ,next_attempt_at_unix_ms) VALUES(?,?,?,?,?,?)",
		id, "cleanup-legacy", at.UnixMilli(), int64(eventlog.Info.Rank()), string(eventlog.NewUserRegistered), at.UnixMilli())

	removed, err := q.Cleanup(ctx, at, retention)
	if err != nil || removed != 3 {
		t.Fatalf("cleanup removed=%d err=%v, want the aged, aged-pending and legacy rows", removed, err)
	}
	want := []string{held.ID, pending.ID, recent.ID}
	slices.Sort(want)
	if got := deliveryIDs(t, ctx, db, id); !slices.Equal(got, want) {
		t.Fatalf("retained=%v want=%v", got, want)
	}
	if removed, err := q.Cleanup(ctx, at, retention); err != nil || removed != 0 {
		t.Fatalf("repeat cleanup removed=%d err=%v", removed, err)
	}
}

// TestNotificationQueueRetiresRemovedDestinations covers GA-NOTIFY-003:
// persisted destinations dropped from configuration must stop queueing.
func TestNotificationQueueRetiresRemovedDestinations(t *testing.T) {
	db, ctx, now := queueFixture(t)
	retired := Identity("slack", "https://hooks.retired.test/a")
	kept := Identity("slack", "https://hooks.kept.test/a")
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: retired, Kind: "slack", Level: eventlog.Info}, {Name: kept, Kind: "slack", Level: eventlog.Info}}, 1); err != nil {
		t.Fatal(err)
	}
	putEvent(t, db, eventlog.TestEvent("retire-both", "", now))
	if got := deliveryIDs(t, ctx, db, retired); len(got) != 1 {
		t.Fatalf("configured destination queued %v, want one row", got)
	}
	q, err := NewRhizaQueue(ctx, db, []Target{{Name: kept, Kind: "slack", Level: eventlog.Info}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if enabled := targetEnabled(t, ctx, db, retired); enabled != 0 {
		t.Fatalf("retired destination enabled=%d, want 0", enabled)
	}
	if enabled := targetEnabled(t, ctx, db, kept); enabled != 1 {
		t.Fatalf("configured destination enabled=%d, want 1", enabled)
	}
	putEvent(t, db, eventlog.TestEvent("retire-kept", "", now.Add(time.Second)))
	if got := deliveryIDs(t, ctx, db, retired); len(got) != 1 {
		t.Fatalf("retired destination queued fresh work: %v", got)
	}
	if got := deliveryIDs(t, ctx, db, kept); len(got) != 2 {
		t.Fatalf("configured destination queued %v, want two rows", got)
	}
	if targets, err := q.Targets(ctx); err != nil || len(targets) != 1 || targets[0].Name != kept {
		t.Fatalf("targets=%v err=%v", targets, err)
	}
	if _, err := NewRhizaQueue(ctx, db, nil, 1); err != nil {
		t.Fatal(err)
	}
	if enabled := targetEnabled(t, ctx, db, kept); enabled != 0 {
		t.Fatalf("destination enabled=%d after notifications were disabled", enabled)
	}
	putEvent(t, db, eventlog.TestEvent("retire-disabled", "", now.Add(2*time.Second)))
	if got := deliveryIDs(t, ctx, db, kept); len(got) != 2 {
		t.Fatalf("disabled destination queued fresh work: %v", got)
	}
}

// TestNotificationQueueFencesSupersededConfiguration covers the rolling-deploy
// half of GA-NOTIFY-003: a pod that restarts on an older configuration must not
// re-enable a destination the current generation retired, and must not roll a
// destination's level back to the old threshold.
func TestNotificationQueueFencesSupersededConfiguration(t *testing.T) {
	db, ctx, now := queueFixture(t)
	retired := Identity("slack", "https://hooks.fence-retired.test/a")
	kept := Identity("slack", "https://hooks.fence-kept.test/a")
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: retired, Kind: "slack", Level: eventlog.Info}, {Name: kept, Kind: "slack", Level: eventlog.Info}}, 1); err != nil {
		t.Fatal(err)
	}
	// Generation 2 drops the retired destination and raises the kept threshold.
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: kept, Kind: "slack", Level: eventlog.Critical}}, 2); err != nil {
		t.Fatal(err)
	}
	if enabled := targetEnabled(t, ctx, db, retired); enabled != 0 {
		t.Fatalf("retired destination enabled=%d after the newer generation, want 0", enabled)
	}
	if level := targetColumn(t, ctx, db, kept, "level"); level != int64(eventlog.Critical.Rank()) {
		t.Fatalf("kept destination level=%d want=%d", level, eventlog.Critical.Rank())
	}

	// The stale pod restarts on generation 1 and re-applies its old configuration.
	stale, err := NewRhizaQueue(ctx, db, []Target{{Name: retired, Kind: "slack", Level: eventlog.Info}, {Name: kept, Kind: "slack", Level: eventlog.Info}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if enabled := targetEnabled(t, ctx, db, retired); enabled != 0 {
		t.Fatalf("superseded pod re-enabled the retired destination: enabled=%d", enabled)
	}
	if level := targetColumn(t, ctx, db, kept, "level"); level != int64(eventlog.Critical.Rank()) {
		t.Fatalf("superseded pod rolled the level back to %d", level)
	}
	// It also must not queue fresh work for a destination it believes in.
	putEvent(t, db, eventlog.TestEvent("fence-stale", "", now))
	if got := deliveryIDs(t, ctx, db, retired); len(got) != 0 {
		t.Fatalf("retired destination received queued work: %v", got)
	}
	// The superseded pod may still serve the destination the current generation
	// kept, but only at the persisted level, and never the retired one.
	if targets, err := stale.Targets(ctx); err != nil || len(targets) != 1 || targets[0].Name != kept || targets[0].Level != eventlog.Critical {
		t.Fatalf("superseded pod targets=%v err=%v", targets, err)
	}

	// The current generation restarts unchanged and keeps its own configuration.
	current, err := NewRhizaQueue(ctx, db, []Target{{Name: kept, Kind: "slack", Level: eventlog.Critical}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if enabled := targetEnabled(t, ctx, db, kept); enabled != 1 {
		t.Fatalf("current generation destination enabled=%d, want 1", enabled)
	}
	if targets, err := current.Targets(ctx); err != nil || len(targets) != 1 || targets[0].Name != kept {
		t.Fatalf("current generation targets=%v err=%v", targets, err)
	}
}

// TestNotificationQueueRejectsInvalidGeneration keeps a bad generation from
// reaching the schema, where a persisted value no later configuration could
// exceed would fence every future deployment.
func TestNotificationQueueRejectsInvalidGeneration(t *testing.T) {
	db, ctx, _ := queueFixture(t)
	for _, generation := range []int64{0, -1} {
		if _, err := NewRhizaQueue(ctx, db, nil, generation); err == nil {
			t.Fatalf("generation %d was accepted", generation)
		}
	}
}

// TestNotificationLegacyWriterFence is the DB-boundary half of GA66-NOTIFY-003:
// the generation gate lives in the new binary, so a legacy pod that restarts
// after a newer generation was claimed would still re-enable a retired
// destination and roll a level back with its unconditional upsert. The v109
// triggers reject any destination write that does not carry the stored
// generation, which is the only fence a writer without the new predicates
// cannot route around.
func TestNotificationLegacyWriterFence(t *testing.T) {
	db, ctx, _ := queueFixture(t)
	kept := Identity("slack", "https://hooks.fence-legacy-kept.test/a")
	retired := Identity("slack", "https://hooks.fence-legacy-retired.test/a")
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: kept, Kind: "slack", Level: eventlog.Info}, {Name: retired, Kind: "slack", Level: eventlog.Info}}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: kept, Kind: "slack", Level: eventlog.Critical}}, 2); err != nil {
		t.Fatal(err)
	}

	// The base binary's exact reconciliation statement, which names neither a
	// generation nor a gate. Both the re-enable and the level rollback abort.
	legacy := []rhiza.SQLStatement{
		{SQL: `INSERT INTO event_notification_targets(target,level,enabled) VALUES(?,?,1) ON CONFLICT(target) DO UPDATE SET level=excluded.level,enabled=1`, Args: []any{retired, int64(eventlog.Info.Rank())}},
		{SQL: `INSERT INTO event_notification_targets(target,level,enabled) VALUES(?,?,1) ON CONFLICT(target) DO UPDATE SET level=excluded.level,enabled=1`, Args: []any{kept, int64(eventlog.Info.Rank())}},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "notify-legacy-writer", Statements: legacy}); err == nil {
		t.Fatal("legacy reconciliation write was admitted after the generation fence")
	}
	if enabled := targetEnabled(t, ctx, db, retired); enabled != 0 {
		t.Fatalf("legacy writer re-enabled the retired destination: enabled=%d", enabled)
	}
	if level := targetColumn(t, ctx, db, kept, "level"); level != int64(eventlog.Critical.Rank()) {
		t.Fatalf("legacy writer rolled the kept level back to %d", level)
	}

	// A row stamped by the current configuration keeps working, so the fence
	// rejects stale writers rather than destination writes in general.
	if _, err := NewRhizaQueue(ctx, db, []Target{{Name: kept, Kind: "slack", Level: eventlog.Critical}}, 2); err != nil {
		t.Fatalf("current configuration was rejected: %v", err)
	}
}

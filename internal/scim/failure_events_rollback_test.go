package scim

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func scimFailureRollbackSQL(t *testing.T, db *rhiza.DB, requestID, sql string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql}); err != nil {
		t.Fatal(err)
	}
}

func scimFailureRollbackScalar(t *testing.T, db *rhiza.DB, sql string, args ...any) any {
	t.Helper()
	r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 1 {
		t.Fatalf("scalar rows=%#v err=%v", r.Rows, err)
	}
	return r.Rows[0][0]
}

func scimFailureRollbackState(t *testing.T, db *rhiza.DB, jobID string) []any {
	t.Helper()
	r, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT status,attempts,lease_token,lease_until_unix_ms,last_error,completed_at_unix_ms,next_attempt_at_unix_ms,revision,request_digest FROM scim_user_outbox WHERE job_id=?`, Args: []any{jobID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("outbox state=%#v err=%v", r.Rows, err)
	}
	return append([]any(nil), r.Rows[0]...)
}

func scimFailureRollbackCompareState(t *testing.T, got, want []any) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("state shape=%#v want=%#v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("state[%d]=%v want=%v", i, got[i], want[i])
		}
	}
}

func seedFinalScimJob(t *testing.T, o *Outbox, eventID string, now time.Time) (Job, string) {
	t.Helper()
	ctx := context.Background()
	if _, err := o.EnqueueUser(ctx, "client-1", User{ExternalID: "ext-1", UserName: "alice", Active: true}, now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found {
		t.Fatalf("lookup seed job=%+v found=%v err=%v", job, found, err)
	}
	jobID := job.ID
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-failure-seed-" + eventID, SQL: `UPDATE scim_user_outbox SET attempts=3,status='processing',lease_token='lease',lease_until_unix_ms=?,last_error='old',next_attempt_at_unix_ms=? WHERE job_id=?`, Args: []any{now.Add(o.LeaseDuration).UnixMilli(), now.UnixMilli(), jobID}}); err != nil {
		t.Fatal(err)
	}
	job, found, err = o.lookupOwned(ctx, jobID, "lease")
	if err != nil || !found {
		t.Fatalf("lookup owned seed job=%+v found=%v err=%v", job, found, err)
	}
	job.leaseToken = "lease"
	return job, jobID
}

func TestSCIMTerminalFailureEventBeforeInsertRollback(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000).UTC()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{MaxAttempts: 3, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 128))})
	job, jobID := seedFinalScimJob(t, o, "before", now)
	before := scimFailureRollbackState(t, o.DB, jobID)
	beforeEvents := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`).(int64)
	beforeOrder := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	scimFailureRollbackSQL(t, o.DB, "scim-failure-before-trigger", `CREATE TRIGGER scim_failure_before_abort BEFORE INSERT ON event_log WHEN NEW.typ='ScimTaskFailed' BEGIN SELECT RAISE(ABORT, 'event sink unavailable'); END`)
	t.Cleanup(func() {
		scimFailureRollbackSQL(t, o.DB, "scim-failure-before-drop", `DROP TRIGGER IF EXISTS scim_failure_before_abort`)
	})

	if err := o.finish(context.Background(), job, now, false, false, "reconcile failed"); err == nil {
		t.Fatal("finish succeeded despite event abort")
	}
	scimFailureRollbackCompareState(t, scimFailureRollbackState(t, o.DB, jobID), before)
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
		t.Fatalf("event count=%v want=%v", got, beforeEvents)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
		t.Fatalf("event highwater=%v want=%v", got, beforeOrder)
	}

	scimFailureRollbackSQL(t, o.DB, "scim-failure-before-drop-now", `DROP TRIGGER scim_failure_before_abort`)
	if err := o.finish(context.Background(), job, now, false, false, "reconcile failed"); err != nil {
		t.Fatal(err)
	}
	state := scimFailureRollbackState(t, o.DB, jobID)
	wantNext := now.Add(o.retryDelay(job, job.Attempts)).UnixMilli()
	if state[0] != "dead" || state[1] != int64(3) || state[2] != nil || state[3] != nil || state[4] != "reconcile failed" || state[5] != now.UnixMilli() || state[6] != wantNext {
		t.Fatalf("terminal state=%#v", state)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log WHERE typ='ScimTaskFailed'`); got != int64(1) {
		t.Fatalf("failure events=%v want=1", got)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder+1 {
		t.Fatalf("event highwater=%v want=%v", got, beforeOrder+1)
	}
	if err := o.finish(context.Background(), job, now, false, false, "stale"); err == nil {
		t.Fatal("stale finish unexpectedly succeeded")
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log WHERE typ='ScimTaskFailed'`); got != int64(1) {
		t.Fatalf("stale finish duplicated events=%v", got)
	}
}

func TestSCIMDeadLetterExpiredEventOrderRollbackAndStaleNoop(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000).UTC()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{MaxAttempts: 3, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 128))})
	ctx := context.Background()
	if _, err := o.EnqueueUser(ctx, "client-1", User{ExternalID: "ext-1", UserName: "alice", Active: true}, now); err != nil {
		t.Fatal(err)
	}
	seeded, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found {
		t.Fatalf("lookup crash seed job=%+v found=%v err=%v", seeded, found, err)
	}
	jobID := seeded.ID
	// A claim that is never finished models a crash on the final attempt.
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-failure-crash-seed", SQL: `UPDATE scim_user_outbox SET attempts=2,status='processing',lease_token='old',lease_until_unix_ms=? WHERE job_id=?`, Args: []any{now.Add(-time.Millisecond).UnixMilli(), jobID}}); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.claim(ctx, now)
	if err != nil || !found || job.Attempts != 3 {
		t.Fatalf("final claim job=%+v found=%v err=%v", job, found, err)
	}
	leaseExpiry := now.Add(o.LeaseDuration)
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT lease_until_unix_ms FROM scim_user_outbox WHERE job_id=?`, jobID); got != leaseExpiry.UnixMilli() {
		t.Fatalf("lease expiry=%v want=%v", got, leaseExpiry.UnixMilli())
	}
	candidate, found, err := o.nextCandidate(ctx, leaseExpiry)
	if err != nil || !found {
		t.Fatalf("expired candidate=%+v found=%v err=%v", candidate, found, err)
	}
	before := scimFailureRollbackState(t, o.DB, jobID)
	beforeEvents := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`).(int64)
	beforeOrder := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	scimFailureRollbackSQL(t, o.DB, "scim-failure-order-trigger", `CREATE TRIGGER scim_failure_order_abort AFTER INSERT ON event_log_order WHEN EXISTS (SELECT 1 FROM event_log WHERE id=NEW.event_id AND typ='ScimTaskFailed') BEGIN SELECT RAISE(ABORT, 'event order unavailable'); END`)
	t.Cleanup(func() {
		scimFailureRollbackSQL(t, o.DB, "scim-failure-order-drop", `DROP TRIGGER IF EXISTS scim_failure_order_abort`)
	})

	if _, err := o.deadLetterExpired(ctx, candidate, leaseExpiry); err == nil {
		t.Fatal("dead-letter succeeded despite event-order abort")
	}
	scimFailureRollbackCompareState(t, scimFailureRollbackState(t, o.DB, jobID), before)
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
		t.Fatalf("event count=%v want=%v", got, beforeEvents)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
		t.Fatalf("event highwater=%v want=%v", got, beforeOrder)
	}
	scimFailureRollbackSQL(t, o.DB, "scim-failure-order-drop-now", `DROP TRIGGER scim_failure_order_abort`)
	if _, err := o.deadLetterExpired(ctx, candidate, leaseExpiry); err != nil {
		t.Fatal(err)
	}
	state := scimFailureRollbackState(t, o.DB, jobID)
	if state[0] != "dead" || state[1] != int64(3) || state[2] != nil || state[3] != nil || state[4] != "maximum attempts reached" || state[5] != leaseExpiry.UnixMilli() || state[6] != now.UnixMilli() {
		t.Fatalf("dead-letter state=%#v", state)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log WHERE typ='ScimTaskFailed'`); got != int64(1) {
		t.Fatalf("failure events=%v want=1", got)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder+1 {
		t.Fatalf("event highwater=%v want=%v", got, beforeOrder+1)
	}
	response, err := o.deadLetterExpired(ctx, candidate, leaseExpiry)
	if err != nil || response.MutationReceipt.RowsAffected != 0 {
		t.Fatalf("stale dead-letter response=%+v err=%v", response, err)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log WHERE typ='ScimTaskFailed'`); got != int64(1) {
		t.Fatalf("stale dead-letter duplicated events=%v", got)
	}
}

func TestSCIMTerminalFailureEventOrderAndUpdateAbortRollback(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		trigger string
	}{
		{name: "order", trigger: `CREATE TRIGGER scim_failure_finish_order_abort AFTER INSERT ON event_log_order WHEN EXISTS (SELECT 1 FROM event_log WHERE id=NEW.event_id AND typ='ScimTaskFailed') BEGIN SELECT RAISE(ABORT, 'event order unavailable'); END`},
		{name: "outbox update", trigger: `CREATE TRIGGER scim_failure_finish_update_abort BEFORE UPDATE ON scim_user_outbox WHEN NEW.status='dead' BEGIN SELECT RAISE(ABORT, 'outbox update unavailable'); END`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now := time.UnixMilli(1_800_000_000_000).UTC()
			o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{MaxAttempts: 3, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 128))})
			job, jobID := seedFinalScimJob(t, o, "finish-"+tc.name, now)
			before := scimFailureRollbackState(t, o.DB, jobID)
			beforeEvents := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`).(int64)
			beforeOrder := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
			scimFailureRollbackSQL(t, o.DB, "scim-failure-finish-trigger", tc.trigger)
			defer scimFailureRollbackSQL(t, o.DB, "scim-failure-finish-drop", `DROP TRIGGER IF EXISTS scim_failure_finish_order_abort`)
			defer scimFailureRollbackSQL(t, o.DB, "scim-failure-finish-update-drop", `DROP TRIGGER IF EXISTS scim_failure_finish_update_abort`)

			if err := o.finish(context.Background(), job, now, false, false, "reconcile failed"); err == nil {
				t.Fatal("finish succeeded despite abort trigger")
			}
			scimFailureRollbackCompareState(t, scimFailureRollbackState(t, o.DB, jobID), before)
			if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
				t.Fatalf("event count=%v want=%v", got, beforeEvents)
			}
			if got := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
				t.Fatalf("event highwater=%v want=%v", got, beforeOrder)
			}
			switch tc.name {
			case "order":
				scimFailureRollbackSQL(t, o.DB, "scim-failure-finish-order-drop-now", `DROP TRIGGER scim_failure_finish_order_abort`)
			case "outbox update":
				scimFailureRollbackSQL(t, o.DB, "scim-failure-finish-update-drop-now", `DROP TRIGGER scim_failure_finish_update_abort`)
			}
			if err := o.finish(context.Background(), job, now, false, false, "reconcile failed"); err != nil {
				t.Fatal(err)
			}
			if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log WHERE typ='ScimTaskFailed'`); got != int64(1) {
				t.Fatalf("failure events=%v want=1", got)
			}
		})
	}
}

func TestSCIMDeadLetterExpiredEventBeforeInsertRollback(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000).UTC()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{MaxAttempts: 3, Random: bytes.NewReader(bytes.Repeat([]byte{10}, 128))})
	ctx := context.Background()
	if _, err := o.EnqueueUser(ctx, "client-1", User{ExternalID: "ext-1", UserName: "alice", Active: true}, now); err != nil {
		t.Fatal(err)
	}
	seeded, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found {
		t.Fatalf("lookup crash seed job=%+v found=%v err=%v", seeded, found, err)
	}
	jobID := seeded.ID
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-failure-before-crash-seed", SQL: `UPDATE scim_user_outbox SET attempts=2,status='processing',lease_token='old',lease_until_unix_ms=? WHERE job_id=?`, Args: []any{now.Add(-time.Millisecond).UnixMilli(), jobID}}); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.claim(ctx, now)
	if err != nil || !found || job.Attempts != 3 {
		t.Fatalf("final claim job=%+v found=%v err=%v", job, found, err)
	}
	expired := now.Add(o.LeaseDuration)
	candidate, found, err := o.nextCandidate(ctx, expired)
	if err != nil || !found {
		t.Fatalf("expired candidate=%+v found=%v err=%v", candidate, found, err)
	}
	before := scimFailureRollbackState(t, o.DB, jobID)
	beforeEvents := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`).(int64)
	beforeOrder := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`).(int64)
	scimFailureRollbackSQL(t, o.DB, "scim-failure-dead-before-trigger", `CREATE TRIGGER scim_failure_dead_before_abort BEFORE INSERT ON event_log WHEN NEW.typ='ScimTaskFailed' BEGIN SELECT RAISE(ABORT, 'event sink unavailable'); END`)
	defer scimFailureRollbackSQL(t, o.DB, "scim-failure-dead-before-drop", `DROP TRIGGER IF EXISTS scim_failure_dead_before_abort`)
	if _, err := o.deadLetterExpired(ctx, candidate, expired); err == nil {
		t.Fatal("dead-letter succeeded despite event abort")
	}
	scimFailureRollbackCompareState(t, scimFailureRollbackState(t, o.DB, jobID), before)
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log`); got != beforeEvents {
		t.Fatalf("event count=%v want=%v", got, beforeEvents)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`); got != beforeOrder {
		t.Fatalf("event highwater=%v want=%v", got, beforeOrder)
	}
	scimFailureRollbackSQL(t, o.DB, "scim-failure-dead-before-drop-now", `DROP TRIGGER scim_failure_dead_before_abort`)
	if _, err := o.deadLetterExpired(ctx, candidate, expired); err != nil {
		t.Fatal(err)
	}
	if got := scimFailureRollbackScalar(t, o.DB, `SELECT COUNT(*) FROM event_log WHERE typ='ScimTaskFailed'`); got != int64(1) {
		t.Fatalf("failure events=%v want=1", got)
	}
}

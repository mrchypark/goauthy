package loginpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

// insertIPFailure writes one login_ip_failures row directly via raw db.Execute.
// The key is digest(ip), matching Check. Raw db.Execute persists well-formed
// rows; malformed values (negative, non-integer) are not stored because the
// STRICT/CHECK schema rejects them, so they cannot be used as fixtures.
func insertIPFailure(t *testing.T, db *rhiza.DB, ip string, failures, blockedUntil, updated int64) {
	t.Helper()
	if _, err := db.Execute(context.Background(), rhiza.ExecuteRequest{
		RequestID: "test-ip-failure",
		SQL:       `INSERT INTO login_ip_failures (key_digest,failures,blocked_until_unix_ms,updated_at_unix_ms) VALUES (?, ?, ?, ?)`,
		Args:      []any{digest(ip), failures, blockedUntil, updated},
	}); err != nil {
		t.Fatal(err)
	}
}

// insertMeanValue writes one login_timing row directly via raw db.Execute.
// The schema enforces success_mean_unix_ms > 0, so zero/negative/text values
// are not stored and cannot be used as fixtures.
func insertMeanValue(t *testing.T, db *rhiza.DB, mean int64) {
	t.Helper()
	if _, err := db.Execute(context.Background(), rhiza.ExecuteRequest{
		RequestID: "test-mean",
		SQL:       `INSERT INTO login_timing (id,success_mean_unix_ms) VALUES (1, ?)`,
		Args:      []any{mean},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSingleQueryMissingBothDefaultFloor(t *testing.T) {
	t.Parallel()
	store := NewStore(testDB(t))
	now := time.UnixMilli(1_700_000_000_000).UTC()
	status, err := store.Check(context.Background(), "192.0.2.10", now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Failures != 0 || !status.BlockedUntil.IsZero() {
		t.Fatalf("zero failure states: status=%+v", status)
	}
	if status.Mean != DefaultSuccessFloor {
		t.Fatalf("default floor: mean=%v want=%v", status.Mean, DefaultSuccessFloor)
	}
}

func TestCheckSingleQueryMissingIPPresentMean(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	insertMeanValue(t, db, 2500)
	store := NewStore(db)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	status, err := store.Check(context.Background(), "192.0.2.11", now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Failures != 0 || !status.BlockedUntil.IsZero() {
		t.Fatalf("no IP row: status=%+v", status)
	}
	if status.Mean != 2500*time.Millisecond {
		t.Fatalf("mean: mean=%v want=2.5s", status.Mean)
	}
}

func TestCheckSingleQueryPresentIPMissingMean(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	insertIPFailure(t, db, "192.0.2.12", 3, 0, now.UnixMilli())
	store := NewStore(db)
	status, err := store.Check(context.Background(), "192.0.2.12", now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Failures != 3 {
		t.Fatalf("failures: status=%+v", status)
	}
	if !status.BlockedUntil.IsZero() {
		t.Fatalf("blocked: status=%+v", status)
	}
	if status.Mean != DefaultSuccessFloor {
		t.Fatalf("default floor when mean absent: mean=%v want=%v", status.Mean, DefaultSuccessFloor)
	}
}

func TestCheckSingleQueryIdleIPWithMean(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	insertIPFailure(t, db, "192.0.2.13", 9, 0, now.Add(-failureIdleTTL).UnixMilli())
	insertMeanValue(t, db, 2500)
	store := NewStore(db)
	status, err := store.Check(context.Background(), "192.0.2.13", now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Failures != 0 || !status.BlockedUntil.IsZero() {
		t.Fatalf("idle resets failure state: status=%+v", status)
	}
	if status.Mean != 2500*time.Millisecond {
		t.Fatalf("idle keeps mean: mean=%v want=2.5s", status.Mean)
	}
}

func TestCheckSingleQueryActiveBlocked(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	blockedUntil := now.Add(time.Minute)
	insertIPFailure(t, db, "192.0.2.14", 5, blockedUntil.UnixMilli(), now.UnixMilli())
	insertMeanValue(t, db, 2500)
	store := NewStore(db)
	status, err := store.Check(context.Background(), "192.0.2.14", now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Failures != 5 {
		t.Fatalf("failures: status=%+v", status)
	}
	if !status.BlockedUntil.Equal(blockedUntil) {
		t.Fatalf("blocked until: status=%+v want=%v", status, blockedUntil)
	}
	if status.Mean != 2500*time.Millisecond {
		t.Fatalf("mean: mean=%v want=2.5s", status.Mean)
	}
}

func TestCheckSingleQueryZeroFailureStates(t *testing.T) {
	t.Parallel()
	store := NewStore(testDB(t))
	now := time.UnixMilli(1_700_000_000_000).UTC()
	status, err := store.Check(context.Background(), "192.0.2.18", now)
	if err != nil {
		t.Fatal(err)
	}
	if status != (Status{Mean: DefaultSuccessFloor}) {
		t.Fatalf("zero failure states: status=%+v", status)
	}
}

// The two defensive checks below are reachable natively: updated_at_unix_ms has
// no schema bound (forward clock is storable) and success_mean_unix_ms has no
// upper bound (out-of-range mean is storable). Check must reject both with
// ErrInvalid. The remaining defensive checks (IP row shape/type/non-negative,
// mean row shape/type/zero/negative) are enforced by the STRICT/CHECK schema,
// so the malformed rows cannot be stored and those Go checks are unreachable
// through the native store; they are preserved by code inspection.

func TestCheckSingleQueryForwardClock(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	insertIPFailure(t, db, "192.0.2.22", 1, 0, now.Add(time.Hour).UnixMilli())
	store := NewStore(db)
	if _, err := store.Check(context.Background(), "192.0.2.22", now); err != ErrInvalid {
		t.Fatalf("forward clock: err=%v want=ErrInvalid", err)
	}
}

func TestCheckSingleQueryMeanOutOfBoundsHigh(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	insertMeanValue(t, db, maxSuccessMean.Milliseconds()+1)
	store := NewStore(db)
	if _, err := store.Check(context.Background(), "192.0.2.23", now); err != ErrInvalid {
		t.Fatalf("out of bounds mean: err=%v want=ErrInvalid", err)
	}
}

func TestCheckSingleQueryDelayUnchanged(t *testing.T) {
	t.Parallel()
	if got := Delay(Status{}, 0); got != 0 {
		t.Fatalf("empty status delay=%v want=0", got)
	}
	if got := Delay(Status{Failures: 5, Mean: time.Second}, 250*time.Millisecond); got != 15*time.Second+750*time.Millisecond {
		t.Fatalf("delay=%v", got)
	}
	if got := Delay(Status{Failures: 25, Mean: DefaultSuccessFloor}, 0); got != DefaultSuccessFloor+25*20*time.Second {
		t.Fatalf("delay=%v", got)
	}
	blocked := Status{BlockedUntil: time.Now().Add(time.Hour)}
	if got := Delay(blocked, 0); got != 0 {
		t.Fatalf("blocked delay=%v want=0", got)
	}
}

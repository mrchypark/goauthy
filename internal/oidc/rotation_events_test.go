package oidc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestActivatePreparedSigningKeyEmitsOneJWKSEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	active, err := EnsureSigningKey(ctx, db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSigningKey(ctx, db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='JwksRotated'`, Consistency: rhiza.ConsistencyLinearizable}); err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatalf("early event=%#v err=%v", rows.Rows, err)
	}
	retireAfter := prepared.ActivatesAfter.Add(MinimumSigningKeyRetirement)
	activationAt := prepared.ActivatesAfter
	if _, err := ActivatePreparedSigningKey(ctx, db, keyring, issuer, active.PublicJWK.KeyID, prepared.PendingKID, retireAfter, activationAt.Add(-time.Millisecond)); err == nil {
		t.Fatal("premature activation accepted")
	}
	if got := rotationOrderHighwater(t, db); got != 0 {
		t.Fatalf("premature activation emitted event: highwater=%d", got)
	}
	if result, err := ActivatePreparedSigningKey(ctx, db, keyring, issuer, active.PublicJWK.KeyID, prepared.PendingKID, retireAfter, activationAt); err != nil || !result.Activated {
		t.Fatalf("activation=%#v err=%v", result, err)
	}
	if _, err := ActivatePreparedSigningKey(ctx, db, keyring, issuer, active.PublicJWK.KeyID, prepared.PendingKID, retireAfter.Add(time.Hour), prepared.ActivatesAfter.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT level,timestamp,ip,data,text FROM event_log WHERE typ='JwksRotated'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != activationAt.UnixMilli() || rows.Rows[0][2] != nil || rows.Rows[0][3] != nil || rows.Rows[0][4] != nil {
		t.Fatalf("rotation event=%#v err=%v", rows.Rows, err)
	}
}

func TestActivatePreparedSigningKeyEventFailureRollsBackAndRetryEmitsOnce(t *testing.T) {
	t.Parallel()
	for _, failure := range []struct{ name, trigger string }{
		{"event_insert", `CREATE TRIGGER rotation_event_fail BEFORE INSERT ON event_log BEGIN SELECT RAISE(ABORT,'event failure'); END`},
		{"key_activation", `CREATE TRIGGER rotation_event_fail BEFORE UPDATE ON oidc_signing_keys WHEN NEW.state='active' BEGIN SELECT RAISE(ABORT,'activation failure'); END`},
	} {
		t.Run(failure.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db := testDB(t)
			keyring := testKeyring(t, "master-1")
			issuer := "https://id.example.com"
			now := time.Unix(1_800_000_000, 0).UTC()
			active, err := EnsureSigningKey(ctx, db, keyring, issuer, now)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := PrepareSigningKey(ctx, db, keyring, issuer, now)
			if err != nil {
				t.Fatal(err)
			}
			retireAfter := prepared.ActivatesAfter.Add(MinimumSigningKeyRetirement)
			beforeOrder := rotationOrderHighwater(t, db)
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rotation-event-fail-trigger", SQL: failure.trigger}); err != nil {
				t.Fatal(err)
			}
			if _, err := ActivatePreparedSigningKey(ctx, db, keyring, issuer, active.PublicJWK.KeyID, prepared.PendingKID, retireAfter, prepared.ActivatesAfter); err == nil {
				t.Fatal("activation unexpectedly succeeded")
			}
			state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state FROM oidc_signing_keys WHERE kid IN (?,?) ORDER BY state`, Args: []any{active.PublicJWK.KeyID, prepared.PendingKID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(state.Rows) != 2 || state.Rows[0][0] != "active" || state.Rows[1][0] != "pending" {
				t.Fatalf("key state=%#v err=%v", state.Rows, err)
			}
			if got := rotationOrderHighwater(t, db); got != beforeOrder {
				t.Fatalf("order highwater changed on rollback: before=%d after=%d", beforeOrder, got)
			}
			rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM event_log),(SELECT COUNT(*) FROM event_log_order)`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) {
				t.Fatalf("rollback left event/order rows=%v err=%v", rows.Rows, err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rotation-event-drop-trigger", SQL: `DROP TRIGGER rotation_event_fail`}); err != nil {
				t.Fatal(err)
			}
			if result, err := ActivatePreparedSigningKey(ctx, db, keyring, issuer, active.PublicJWK.KeyID, prepared.PendingKID, retireAfter.Add(time.Hour), prepared.ActivatesAfter); err != nil || !result.Activated {
				t.Fatalf("retry=%#v err=%v", result, err)
			}
			count, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='JwksRotated'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || count.Rows[0][0] != int64(1) {
				t.Fatalf("events=%#v err=%v", count.Rows, err)
			}
			if got := rotationOrderHighwater(t, db); got != beforeOrder+1 {
				t.Fatalf("retry did not advance order highwater: before=%d after=%d", beforeOrder, got)
			}
		})
	}
}

func rotationOrderHighwater(t *testing.T, db *rhiza.DB) int64 {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("order highwater=%#v err=%v", rows.Rows, err)
	}
	return rows.Rows[0][0].(int64)
}

func TestActivatePreparedSigningKeyConcurrentTimesEmitsOneEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	keyring := testKeyring(t, "master-1")
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	active, err := EnsureSigningKey(ctx, db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSigningKey(ctx, db, keyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	results := make([]RotationResult, len(errs))
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			at := prepared.ActivatesAfter.Add(time.Duration(i) * time.Millisecond)
			results[i], errs[i] = ActivatePreparedSigningKey(ctx, db, keyring, issuer, active.PublicJWK.KeyID, prepared.PendingKID, at.Add(MinimumSigningKeyRetirement), at)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil || results[i].Active.PublicJWK.KeyID != prepared.PendingKID {
			t.Fatalf("concurrent activation %d: key=%s err=%v", i, results[i].Active.PublicJWK.KeyID, err)
		}
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='JwksRotated'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(1) {
		t.Fatalf("concurrent events=%#v err=%v", rows.Rows, err)
	}
}

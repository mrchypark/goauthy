package dcr

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRewrapIdempotencyBatchIsBoundedAndSkipsActiveOrExpiredRows(t *testing.T) {
	ctx, store, db := testStore(t)
	old, active := rewrapKeyrings(t)
	store.keyring = active
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	seedRewrapRows(t, ctx, db, old, now, 33)
	activeEnvelope, err := active.SealEnvelope(idempotencyPurpose, []byte(`{"active":true}`))
	if err != nil {
		t.Fatal(err)
	}
	expiredEnvelope, err := old.SealEnvelope(idempotencyPurpose, []byte(`{"expired":true}`))
	if err != nil {
		t.Fatal(err)
	}
	seedRows := []rhiza.SQLStatement{
		{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digestString("active-principal"), digestString("active-key"), digestString("active-request"), "active", base64.RawURLEncoding.EncodeToString(activeEnvelope), now.Add(time.Hour).UnixMilli(), now.UnixMilli()}},
		{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digestString("expired-principal"), digestString("expired-key"), digestString("expired-request"), "expired", base64.RawURLEncoding.EncodeToString(expiredEnvelope), now.UnixMilli(), now.Add(-time.Hour).UnixMilli()}},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "dcr-rewrap-active-expired", Statements: seedRows}); err != nil {
		t.Fatal(err)
	}

	cursor, updated, err := store.RewrapIdempotencyBatch(ctx, "")
	if err != nil || updated > maxIdempotencyRewrapBatch || cursor == "" {
		t.Fatalf("first batch cursor=%q updated=%d err=%v", cursor, updated, err)
	}
	total := updated
	for cursor != "" {
		cursor, updated, err = store.RewrapIdempotencyBatch(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if updated > maxIdempotencyRewrapBatch {
			t.Fatalf("batch updated=%d", updated)
		}
		total += updated
	}
	if total != 33 {
		t.Fatalf("rewrapped rows=%d want 33", total)
	}
	for _, name := range []string{"active", "expired"} {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT response_envelope FROM dcr_registration_idempotency WHERE client_id=?`, Args: []any{name}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 {
			t.Fatalf("%s row=%#v err=%v", name, result.Rows, err)
		}
		envelope, err := base64.RawURLEncoding.DecodeString(result.Rows[0][0].(string))
		if err != nil {
			t.Fatal(err)
		}
		wantKey := "master-new"
		if name == "expired" {
			wantKey = "master-old"
		}
		keyID, err := active.PurposeEnvelopeKeyID(idempotencyPurpose, envelope)
		if err != nil || keyID != wantKey {
			t.Fatalf("%s key=%q err=%v want=%q", name, keyID, err, wantKey)
		}
	}
}

func TestRewrapIdempotencyPreflightsBeforeMutation(t *testing.T) {
	ctx, store, db := testStore(t)
	old, active := rewrapKeyrings(t)
	store.keyring = active
	now := time.UnixMilli(100_000).UTC()
	store.now = func() time.Time { return now }
	seedRewrapRows(t, ctx, db, old, now, 1)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "dcr-rewrap-tampered", SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digestString("tampered-principal"), digestString("tampered-key"), digestString("tampered-request"), "tampered", "not-base64", now.Add(time.Hour).UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RewrapIdempotencyBatch(ctx, ""); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT response_envelope FROM dcr_registration_idempotency WHERE client_id=?`, Args: []any{"client-000"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("valid row=%#v err=%v", result.Rows, err)
	}
	envelope, err := base64.RawURLEncoding.DecodeString(result.Rows[0][0].(string))
	if err != nil {
		t.Fatal(err)
	}
	if keyID, err := active.PurposeEnvelopeKeyID(idempotencyPurpose, envelope); err != nil || keyID != "master-old" {
		t.Fatalf("valid row mutated after preflight failure: key=%q err=%v", keyID, err)
	}
}

func TestRewrapIdempotencyMutationIsAllOrZero(t *testing.T) {
	ctx, store, db := testStore(t)
	old, active := rewrapKeyrings(t)
	now := time.UnixMilli(150_000).UTC()
	store.keyring = active
	store.now = func() time.Time { return now }
	seedRewrapRows(t, ctx, db, old, now, 2)
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT principal_digest,key_digest,request_digest,response_envelope,expires_at_unix_ms FROM dcr_registration_idempotency ORDER BY principal_digest,key_digest`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 {
		t.Fatalf("rows=%#v err=%v", result.Rows, err)
	}
	candidates := make([]idempotencyRewrapCandidate, 2)
	for i, row := range result.Rows {
		oldEnvelope := row[3].(string)
		envelope, err := base64.RawURLEncoding.DecodeString(oldEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		newEnvelope, err := active.RewrapEnvelope(idempotencyPurpose, envelope)
		if err != nil {
			t.Fatal(err)
		}
		candidates[i] = idempotencyRewrapCandidate{
			principalDigest: row[0].(string),
			keyDigest:       row[1].(string),
			requestDigest:   row[2].(string),
			oldEnvelope:     oldEnvelope,
			expiresAt:       row[4].(int64),
			newEnvelope:     base64.RawURLEncoding.EncodeToString(newEnvelope),
		}
	}
	firstBefore := candidates[0].oldEnvelope
	replacement, err := old.SealEnvelope(idempotencyPurpose, []byte(`{"replacement":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "dcr-rewrap-interpose",
		SQL:       `UPDATE dcr_registration_idempotency SET response_envelope=? WHERE principal_digest=? AND key_digest=?`,
		Args:      []any{base64.RawURLEncoding.EncodeToString(replacement), candidates[1].principalDigest, candidates[1].keyDigest},
	}); err != nil {
		t.Fatal(err)
	}
	requestID, sql, args := idempotencyRewrapMutation(now.UnixMilli(), candidates)
	response, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	if response.RowsAffected != 0 {
		t.Fatalf("all-or-zero guard affected %d rows, want zero", response.RowsAffected)
	}
	if got := queryRewrapEnvelope(t, ctx, db, candidates[0]); got != firstBefore {
		t.Fatal("all-or-zero guard partially changed the first row")
	}
	if cursor, updated, err := store.RewrapIdempotencyBatch(ctx, ""); err != nil || cursor != "" || updated != 2 {
		t.Fatalf("retry did not converge after interposition: cursor=%q updated=%d err=%v", cursor, updated, err)
	}
}

func queryRewrapEnvelope(t *testing.T, ctx context.Context, db *rhiza.DB, candidate idempotencyRewrapCandidate) string {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT response_envelope FROM dcr_registration_idempotency WHERE principal_digest=? AND key_digest=?`, Args: []any{candidate.principalDigest, candidate.keyDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("candidate row=%#v err=%v", result.Rows, err)
	}
	return result.Rows[0][0].(string)
}

func TestConcurrentRewrapIdempotencyBatchesConverge(t *testing.T) {
	ctx, _, db := testStore(t)
	old, active := rewrapKeyrings(t)
	now := time.UnixMilli(200_000).UTC()
	seedRewrapRows(t, ctx, db, old, now, 4)
	stores := make([]*Store, 3)
	for i := range stores {
		stores[i] = NewStore(db, Config{Keyring: active, Now: func() time.Time { return now }})
	}
	start := make(chan struct{})
	results := make([]int, len(stores))
	errs := make([]error, len(stores))
	var wg sync.WaitGroup
	for i, concurrentStore := range stores {
		wg.Add(1)
		go func(index int, s *Store) {
			defer wg.Done()
			<-start
			_, results[index], errs[index] = s.RewrapIdempotencyBatch(ctx, "")
		}(i, concurrentStore)
	}
	close(start)
	wg.Wait()
	totalUpdated := 0
	// Every worker sees the same four old rows. The guarded mutation must
	// therefore commit either all four rows or none of them; partial success
	// would advance a cursor past an old-key row and strand it.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
		updated := results[i]
		if updated != 0 && updated != 4 {
			t.Fatalf("worker %d partial result: updated=%d", i, updated)
		}
		totalUpdated += updated
	}
	if totalUpdated != 4 {
		t.Fatalf("workers did not converge exactly once: total updated=%d results=%v", totalUpdated, results)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT response_envelope FROM dcr_registration_idempotency`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 4 {
		t.Fatalf("rows=%#v err=%v", result.Rows, err)
	}
	for _, row := range result.Rows {
		envelope, err := base64.RawURLEncoding.DecodeString(row[0].(string))
		if err != nil {
			t.Fatal(err)
		}
		if keyID, err := active.PurposeEnvelopeKeyID(idempotencyPurpose, envelope); err != nil || keyID != "master-new" {
			t.Fatalf("concurrent rewrap key=%q err=%v", keyID, err)
		}
	}
	if cursor, updated, err := stores[0].RewrapIdempotencyBatch(ctx, ""); err != nil || cursor != "" || updated != 0 {
		t.Fatalf("post-convergence batch cursor=%q updated=%d err=%v", cursor, updated, err)
	}
	statements := []rhiza.SQLStatement{{SQL: `UPDATE dcr_registration_idempotency SET response_envelope=? WHERE principal_digest=?`, Args: []any{"new", "principal"}}}
	if first, second := idempotencyRewrapRequestID(statements), idempotencyRewrapRequestID(statements); first != second {
		t.Fatalf("request ID is not deterministic: %q != %q", first, second)
	}
}

func rewrapKeyrings(t *testing.T) (EnvelopeKeyring, EnvelopeKeyring) {
	t.Helper()
	directory := t.TempDir()
	for name, value := range map[string]byte{"master-old": 0x31, "master-new": 0x32} {
		encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
		if err := os.WriteFile(directory+"/"+name, []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old, err := oidc.LoadKeyring(directory, "master-old")
	if err != nil {
		t.Fatal(err)
	}
	active, err := oidc.LoadKeyring(directory, "master-new")
	if err != nil {
		t.Fatal(err)
	}
	return old, active
}

func seedRewrapRows(t *testing.T, ctx context.Context, db *rhiza.DB, keyring EnvelopeKeyring, now time.Time, count int) {
	t.Helper()
	statements := make([]rhiza.SQLStatement, 0, count)
	for i := range count {
		body := []byte(fmt.Sprintf(`{"index":%d}`, i))
		envelope, err := keyring.SealEnvelope(idempotencyPurpose, body)
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digestString(fmt.Sprintf("principal-%03d", i)), digestString(fmt.Sprintf("key-%03d", i)), digestString(fmt.Sprintf("request-%03d", i)), fmt.Sprintf("client-%03d", i), base64.RawURLEncoding.EncodeToString(envelope), now.Add(time.Hour).UnixMilli(), now.UnixMilli()}})
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "dcr-rewrap-seed", Statements: statements}); err != nil {
		t.Fatal(err)
	}
}

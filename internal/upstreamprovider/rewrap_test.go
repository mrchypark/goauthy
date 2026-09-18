package upstreamprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRewrapTransactionBatchEligibility(t *testing.T) {
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	now := time.Unix(1_900_000_000, 123_000_000).UTC()

	old := testRhizaTransaction()
	old.StateDigest = DigestSHA256("rewrap-old")
	old.CreatedAt, old.ExpiresAt = now.Add(-time.Hour), now.Add(time.Hour)
	if err := oldStore.Save(ctx, old); err != nil {
		t.Fatal(err)
	}
	active := testRhizaTransaction()
	active.StateDigest = DigestSHA256("rewrap-active")
	active.CreatedAt, active.ExpiresAt = now.Add(-time.Hour), now.Add(time.Hour)
	if err := newStore.Save(ctx, active); err != nil {
		t.Fatal(err)
	}
	expired := testRhizaTransaction()
	expired.StateDigest = DigestSHA256("rewrap-expired")
	expired.CreatedAt, expired.ExpiresAt = now.Add(-2*time.Hour), now.Add(-time.Millisecond)
	if err := oldStore.Save(ctx, expired); err != nil {
		t.Fatal(err)
	}
	boundary := testRhizaTransaction()
	boundary.StateDigest = DigestSHA256("rewrap-boundary")
	boundary.CreatedAt, boundary.ExpiresAt = now.Add(-2*time.Hour), now
	if err := oldStore.Save(ctx, boundary); err != nil {
		t.Fatal(err)
	}

	oldEnvelope := transactionEnvelopeText(t, ctx, db, old.StateDigest)
	activeEnvelope := transactionEnvelopeText(t, ctx, db, active.StateDigest)
	expiredEnvelope := transactionEnvelopeText(t, ctx, db, expired.StateDigest)
	boundaryEnvelope := transactionEnvelopeText(t, ctx, db, boundary.StateDigest)
	next, done, updated, err := newStore.RewrapTransactionBatch(ctx, now, "")
	if err != nil {
		t.Fatal(err)
	}
	if next == "" || !done || updated != 1 {
		t.Fatalf("cursor=%q done=%v updated=%d, want one completed update", next, done, updated)
	}
	if got := transactionEnvelopeText(t, ctx, db, active.StateDigest); got != activeEnvelope {
		t.Fatal("active-key envelope changed")
	}
	if got := transactionEnvelopeText(t, ctx, db, expired.StateDigest); got != expiredEnvelope {
		t.Fatal("expired envelope changed")
	}
	if got := transactionEnvelopeText(t, ctx, db, boundary.StateDigest); got != boundaryEnvelope {
		t.Fatal("boundary-expired envelope changed")
	}
	newEnvelope := transactionEnvelopeText(t, ctx, db, old.StateDigest)
	if newEnvelope == oldEnvelope {
		t.Fatal("old-key envelope was not replaced")
	}
	oldPlaintext, err := oldStore.keyring.OpenEnvelope(transactionEnvelopePurpose, mustDecodeEnvelope(t, oldEnvelope))
	if err != nil {
		t.Fatal(err)
	}
	newPlaintext, err := newStore.keyring.OpenEnvelope(transactionEnvelopePurpose, mustDecodeEnvelope(t, newEnvelope))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newPlaintext, oldPlaintext) {
		t.Fatal("rewrap changed transaction plaintext")
	}
}

func TestRewrapTransactionBatchFencedOldWriterRollsBackAndReplacementIsAllowed(t *testing.T) {
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	oldEnvelopeTx := testRhizaTransaction()
	oldEnvelopeTx.StateDigest = DigestSHA256("fenced-rewrap-old")
	oldEnvelopeTx.CreatedAt, oldEnvelopeTx.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
	if err := oldStore.Save(ctx, oldEnvelopeTx); err != nil {
		t.Fatal(err)
	}
	oldWriterTx := testRhizaTransaction()
	oldWriterTx.StateDigest = DigestSHA256("fenced-rewrap-writer")
	oldWriterTx.CreatedAt, oldWriterTx.ExpiresAt = oldEnvelopeTx.CreatedAt, oldEnvelopeTx.ExpiresAt
	if err := newStore.Save(ctx, oldWriterTx); err != nil {
		t.Fatal(err)
	}
	before := transactionEnvelopeText(t, ctx, db, oldWriterTx.StateDigest)
	fenceMasterKeyRetirementForTest(t, ctx, db, "master-old", "master-new")
	if _, _, _, err := oldStore.RewrapTransactionBatch(ctx, now, ""); err == nil {
		t.Fatal("fenced old writer was accepted")
	}
	if got := transactionEnvelopeText(t, ctx, db, oldWriterTx.StateDigest); got != before {
		t.Fatal("fenced old writer partially changed the envelope")
	}
	if _, _, updated, err := newStore.RewrapTransactionBatch(ctx, now, ""); err != nil || updated != 1 {
		t.Fatalf("replacement rewrap updated=%d err=%v", updated, err)
	}
	keyID, err := newStore.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, mustDecodeEnvelope(t, transactionEnvelopeText(t, ctx, db, oldEnvelopeTx.StateDigest)))
	if err != nil || keyID != "master-new" {
		t.Fatalf("rewrapped envelope key=%q err=%v", keyID, err)
	}
}

func TestRewrapTransactionBatchTamperDoesNotPartiallyWrite(t *testing.T) {
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	first, second := testRhizaTransaction(), testRhizaTransaction()
	first.StateDigest = DigestSHA256("rewrap-tamper-first")
	second.StateDigest = DigestSHA256("rewrap-tamper-second")
	first.CreatedAt, first.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
	second.CreatedAt, second.ExpiresAt = first.CreatedAt, first.ExpiresAt
	if err := oldStore.Save(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Save(ctx, second); err != nil {
		t.Fatal(err)
	}
	firstBefore := transactionEnvelopeText(t, ctx, db, first.StateDigest)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rewrap-test-tamper", SQL: `UPDATE upstream_provider_transactions SET secret_envelope=? WHERE state_digest=?`, Args: []any{"tampered", second.StateDigest}}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := newStore.RewrapTransactionBatch(ctx, now, ""); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
	if got := transactionEnvelopeText(t, ctx, db, first.StateDigest); got != firstBefore {
		t.Fatal("valid row was partially rewrapped after tamper")
	}
}

func TestRewrapTransactionBatchPreservesConsume(t *testing.T) {
	ctx, _, oldStore, newStore := testRotatingRhizaStore(t)
	tx := testRhizaTransaction()
	if err := oldStore.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, _, updated, err := newStore.RewrapTransactionBatch(ctx, tx.CreatedAt.Add(time.Second), ""); err != nil || updated != 1 {
		t.Fatalf("rewrap updated=%d err=%v", updated, err)
	}
	got, err := newStore.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.StateDigest != tx.StateDigest || got.Nonce != tx.Nonce || got.PKCEVerifier != tx.PKCEVerifier {
		t.Fatalf("consumed transaction changed: got=%#v want=%#v", got, tx)
	}
}

func TestRewrapTransactionBatchRespectsUpdateBoundAndCursor(t *testing.T) {
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	stateDigests := make([]string, 33)
	for i := range stateDigests {
		tx := testRhizaTransaction()
		tx.StateDigest = DigestSHA256(fmt.Sprintf("rewrap-many-%d", i))
		tx.CreatedAt, tx.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
		stateDigests[i] = tx.StateDigest
		if err := oldStore.Save(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}
	next, done, updated, err := newStore.RewrapTransactionBatch(ctx, now, "")
	if err != nil {
		t.Fatal(err)
	}
	if next == "" || done || updated != transactionRewrapUpdateLimit {
		t.Fatalf("first batch cursor=%q done=%v updated=%d", next, done, updated)
	}
	next, done, updated, err = newStore.RewrapTransactionBatch(ctx, now, next)
	if err != nil {
		t.Fatal(err)
	}
	if next == "" || !done || updated != 1 {
		t.Fatalf("second batch cursor=%q done=%v updated=%d", next, done, updated)
	}
	for _, stateDigest := range stateDigests {
		text := transactionEnvelopeText(t, ctx, db, stateDigest)
		keyID, err := newStore.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, mustDecodeEnvelope(t, text))
		if err != nil || keyID != "master-new" {
			t.Fatalf("state %q key=%q err=%v, want master-new", stateDigest, keyID, err)
		}
	}
}

func TestRewrapTransactionBatchAdvancesPastActiveScan(t *testing.T) {
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	stateDigests := make([]string, 130)
	for i := range stateDigests {
		stateDigests[i] = DigestSHA256(fmt.Sprintf("rewrap-mixed-%03d", i))
	}
	sort.Strings(stateDigests)
	for i, stateDigest := range stateDigests {
		tx := testRhizaTransaction()
		tx.StateDigest = stateDigest
		tx.CreatedAt, tx.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
		store := newStore
		if i == 0 || i == len(stateDigests)-1 {
			store = oldStore
		}
		if err := store.Save(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}

	next, done, updated, err := newStore.RewrapTransactionBatch(ctx, now, "")
	if err != nil {
		t.Fatal(err)
	}
	if next == "" || done || updated != 1 {
		t.Fatalf("first mixed batch cursor=%q done=%v updated=%d", next, done, updated)
	}
	next, done, updated, err = newStore.RewrapTransactionBatch(ctx, now, next)
	if err != nil {
		t.Fatal(err)
	}
	if next == "" || !done || updated != 1 {
		t.Fatalf("second mixed batch cursor=%q done=%v updated=%d", next, done, updated)
	}
	for _, stateDigest := range []string{stateDigests[0], stateDigests[len(stateDigests)-1]} {
		text := transactionEnvelopeText(t, ctx, db, stateDigest)
		keyID, err := newStore.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, mustDecodeEnvelope(t, text))
		if err != nil || keyID != "master-new" {
			t.Fatalf("state %q key=%q err=%v, want master-new", stateDigest, keyID, err)
		}
	}
}

func TestRewrapTransactionBatchConcurrentCASHasOneMultiRowWinner(t *testing.T) {
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	stateDigests := make([]string, 3)
	for i := range stateDigests {
		tx := testRhizaTransaction()
		tx.StateDigest = DigestSHA256(fmt.Sprintf("rewrap-concurrent-%d", i))
		tx.CreatedAt, tx.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
		stateDigests[i] = tx.StateDigest
		if err := oldStore.Save(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	updates := make(chan int64, 3)
	errs := make(chan error, 3)
	var wait sync.WaitGroup
	for range 3 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, _, updated, err := newStore.RewrapTransactionBatch(ctx, now, "")
			updates <- updated
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(updates)
	close(errs)
	var total int64
	for updated := range updates {
		if updated != 0 && updated != int64(len(stateDigests)) {
			t.Fatalf("partial concurrent update=%d, want 0 or %d", updated, len(stateDigests))
		}
		total += updated
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if total != int64(len(stateDigests)) {
		t.Fatalf("total CAS updates=%d, want one multi-row winner", total)
	}
	for _, stateDigest := range stateDigests {
		text := transactionEnvelopeText(t, ctx, db, stateDigest)
		keyID, err := newStore.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, mustDecodeEnvelope(t, text))
		if err != nil || keyID != "master-new" {
			t.Fatalf("state %q final key=%q err=%v, want master-new", stateDigest, keyID, err)
		}
	}
}

func TestTransactionRewrapMutationIsAllOrZero(t *testing.T) {
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	transactions := make([]Transaction, 2)
	rows := make([]transactionRewrapRow, 2)
	for i := range transactions {
		tx := testRhizaTransaction()
		tx.StateDigest = DigestSHA256(fmt.Sprintf("rewrap-guard-%d", i))
		tx.CreatedAt, tx.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
		transactions[i] = tx
		if err := oldStore.Save(ctx, tx); err != nil {
			t.Fatal(err)
		}
		rows[i] = transactionRewrapRow{stateDigest: tx.StateDigest, envelopeText: transactionEnvelopeText(t, ctx, db, tx.StateDigest), expiresAtUnix: tx.ExpiresAt.UnixMilli(), newEnvelopeText: "prepared-" + fmt.Sprint(i)}
	}
	firstBefore := rows[0].envelopeText
	replacement, err := oldStore.keyring.SealEnvelope(transactionEnvelopePurpose, []byte("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rewrap-guard-interpose", SQL: `UPDATE upstream_provider_transactions SET secret_envelope=? WHERE state_digest=?`, Args: []any{base64.RawURLEncoding.EncodeToString(replacement), rows[1].stateDigest}}); err != nil {
		t.Fatal(err)
	}
	statement := transactionRewrapMutation(now, rows)
	response, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "rewrap-guard-test", SQL: statement.SQL, Args: statement.Args})
	if err != nil {
		t.Fatal(err)
	}
	if response.RowsAffected != 0 {
		t.Fatalf("guard affected %d rows, want zero", response.RowsAffected)
	}
	if got := transactionEnvelopeText(t, ctx, db, transactions[0].StateDigest); got != firstBefore {
		t.Fatal("all-or-zero guard partially changed the first row")
	}
	if _, _, updated, err := newStore.RewrapTransactionBatch(ctx, now, ""); err != nil || updated != 2 {
		t.Fatalf("retry did not converge after interposition: updated=%d err=%v", updated, err)
	}
}

func TestTransactionRewrapRequestIDDeterministic(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	row := transactionRewrapRow{stateDigest: DigestSHA256("state"), envelopeText: "old", expiresAtUnix: now.Add(time.Hour).UnixMilli(), newEnvelopeText: "new"}
	if first, second := transactionRewrapRequestID("master-new", now, []transactionRewrapRow{row}), transactionRewrapRequestID("master-new", now, []transactionRewrapRow{row}); first != second {
		t.Fatalf("same prepared batch IDs differ: %q != %q", first, second)
	}
	if first, second := transactionRewrapRequestID("master-new", now, []transactionRewrapRow{row}), transactionRewrapRequestID("master-new", now.Add(time.Millisecond), []transactionRewrapRow{row}); first == second {
		t.Fatal("request ID omitted the mutation's expiry clock")
	}
}

func testRotatingRhizaStore(t *testing.T) (context.Context, *rhiza.DB, *RhizaStore, *RhizaStore) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "upstream-rewrap-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, value := range map[string]byte{"master-old": 0x11, "master-new": 0x22} {
		key := bytes.Repeat([]byte{value}, 32)
		encoded := base64.RawURLEncoding.EncodeToString(key)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldKeyring, err := oidc.LoadKeyring(dir, "master-old")
	if err != nil {
		t.Fatal(err)
	}
	newKeyring, err := oidc.LoadKeyring(dir, "master-new")
	if err != nil {
		t.Fatal(err)
	}
	oldStore, err := NewRhizaStore(db, oldKeyring)
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := NewRhizaStore(db, newKeyring)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, db, oldStore, newStore
}

func transactionEnvelopeText(t *testing.T, ctx context.Context, db *rhiza.DB, stateDigest string) string {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_envelope FROM upstream_provider_transactions WHERE state_digest=?`, Args: []any{stateDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("envelope query rows=%v err=%v", result.Rows, err)
	}
	text, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatalf("envelope has type %T", result.Rows[0][0])
	}
	return text
}

func mustDecodeEnvelope(t *testing.T, text string) []byte {
	t.Helper()
	envelope, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

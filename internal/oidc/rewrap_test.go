package oidc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRewrapSigningKeyEnvelopeBatchRewrapsAllStates(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	oldKeyring := fixedKeyring("master-a")
	active, err := EnsureSigningKey(context.Background(), db, oldKeyring, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	insertSigningRewrapRow(t, db, oldKeyring, issuer, bytes.Repeat([]byte{2}, ed25519.SeedSize), "pending", now)
	insertSigningRewrapRow(t, db, oldKeyring, issuer, bytes.Repeat([]byte{3}, ed25519.SeedSize), "retiring", now.Add(time.Second))

	rotated := fixedKeyring("master-b")
	batch, err := RewrapSigningKeyEnvelopeBatch(context.Background(), db, rotated, issuer, "")
	if err != nil {
		t.Fatal(err)
	}
	if batch.Rewrapped != 3 || !batch.Done || batch.Cursor == "" {
		t.Fatalf("batch=%+v", batch)
	}
	if _, err := LoadActiveSigningKey(context.Background(), db, rotated, issuer); err != nil {
		t.Fatalf("active signing key after rewrap: %v", err)
	}
	assertSigningRowsUseKey(t, db, rotated, issuer, "master-b")

	second, err := RewrapSigningKeyEnvelopeBatch(context.Background(), db, rotated, issuer, "")
	if err != nil {
		t.Fatal(err)
	}
	if second.Rewrapped != 0 || !second.Done {
		t.Fatalf("second batch=%+v", second)
	}
	_ = active
}

func TestRewrapSigningKeyEnvelopeBatchCursorIsBounded(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	oldKeyring := fixedKeyring("master-a")
	if _, err := EnsureSigningKey(context.Background(), db, oldKeyring, issuer, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		insertSigningRewrapRow(t, db, oldKeyring, issuer, bytes.Repeat([]byte{byte(i + 10)}, ed25519.SeedSize), "retiring", now.Add(time.Duration(i+1)*time.Second))
	}
	rotated := fixedKeyring("master-b")
	first, err := RewrapSigningKeyEnvelopeBatch(context.Background(), db, rotated, issuer, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Rewrapped != signingKeyRewrapBatchSize || first.Done || first.Cursor == "" {
		t.Fatalf("first batch=%+v", first)
	}
	second, err := RewrapSigningKeyEnvelopeBatch(context.Background(), db, rotated, issuer, first.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if second.Rewrapped != 9 || !second.Done {
		t.Fatalf("second batch=%+v", second)
	}
	assertSigningRowsUseKey(t, db, rotated, issuer, "master-b")
}

func TestRewrapSigningKeyEnvelopeBatchTamperHasNoPartialMutation(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	oldKeyring := fixedKeyring("master-a")
	if _, err := EnsureSigningKey(context.Background(), db, oldKeyring, issuer, now); err != nil {
		t.Fatal(err)
	}
	insertSigningRewrapRow(t, db, oldKeyring, issuer, bytes.Repeat([]byte{4}, ed25519.SeedSize), "retiring", now.Add(time.Second))
	insertSigningRewrapRow(t, db, oldKeyring, issuer, bytes.Repeat([]byte{5}, ed25519.SeedSize), "retiring", now.Add(2*time.Second))
	rows := signingEnvelopeRows(t, db)
	var tamperKID string
	for kid := range rows {
		tamperKID = kid
		break
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "oidc-rewrap-test-tamper",
		SQL:       `UPDATE oidc_signing_keys SET private_envelope=? WHERE kid=?`,
		Args:      []any{"tampered", tamperKID},
	}); err != nil {
		t.Fatal(err)
	}
	before := signingEnvelopeRows(t, db)
	if _, err := RewrapSigningKeyEnvelopeBatch(context.Background(), db, fixedKeyring("master-b"), issuer, ""); err == nil {
		t.Fatal("tampered row was accepted")
	}
	after := signingEnvelopeRows(t, db)
	if len(before) != len(after) {
		t.Fatalf("row count changed: before=%d after=%d", len(before), len(after))
	}
	for kid, envelope := range before {
		if after[kid] != envelope {
			t.Fatalf("row %q changed after preflight failure", kid)
		}
	}
}

func TestRewrapSigningKeyEnvelopeBatchConcurrentWorkersConverge(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()
	oldKeyring := fixedKeyring("master-a")
	if _, err := EnsureSigningKey(context.Background(), db, oldKeyring, issuer, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		insertSigningRewrapRow(t, db, oldKeyring, issuer, bytes.Repeat([]byte{byte(i + 70)}, ed25519.SeedSize), "retiring", now.Add(time.Duration(i+1)*time.Second))
	}

	rotated := fixedKeyring("master-b")
	results := make([]SigningKeyRewrapBatchResult, 3)
	errs := make([]error, 3)
	var wait sync.WaitGroup
	for i := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = RewrapSigningKeyEnvelopeBatch(context.Background(), db, rotated, issuer, "")
		}(i)
	}
	wait.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
		if results[i].Rewrapped != 0 && results[i].Rewrapped != 3 {
			t.Fatalf("worker %d partial result: %+v", i, results[i])
		}
	}
	assertSigningRowsUseKey(t, db, rotated, issuer, "master-b")
}

func insertSigningRewrapRow(t *testing.T, db *rhiza.DB, keyring *Keyring, issuer string, seed []byte, state string, createdAt time.Time) string {
	t.Helper()
	key, publicJSON, kid, err := signingKeyFromSeed(seed, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sealEnvelope(keyring, issuer, kid, seed)
	if err != nil {
		t.Fatal(err)
	}
	var activates, retires any
	switch state {
	case "pending":
		activates = createdAt.Add(time.Minute).UnixMilli()
	case "retiring":
		retires = createdAt.Add(time.Hour).UnixMilli()
	default:
		t.Fatalf("unsupported test state %q", state)
	}
	digest := sha256.Sum256([]byte("insert/" + kid))
	_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "oidc-rewrap-test-insert-" + base64.RawURLEncoding.EncodeToString(digest[:8]),
		SQL: `INSERT INTO oidc_signing_keys
			(kid,public_jwk,private_envelope,state,created_at_unix_ms,activates_after_unix_ms,retire_after_unix_ms)
			VALUES (?,?,?,?,?,?,?)`,
		Args: []any{key.PublicJWK.KeyID, string(publicJSON), base64.RawURLEncoding.EncodeToString(envelope), state, createdAt.UnixMilli(), activates, retires},
	})
	if err != nil {
		t.Fatal(err)
	}
	return kid
}

func signingEnvelopeRows(t *testing.T, db *rhiza.DB) map[string]string {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT kid,private_envelope FROM oidc_signing_keys ORDER BY kid`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]string, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 2 {
			t.Fatalf("invalid signing row: %v", row)
		}
		kid, ok := row[0].(string)
		envelope, envelopeOK := row[1].(string)
		if !ok || !envelopeOK {
			t.Fatalf("invalid signing row types: %v", row)
		}
		rows[kid] = envelope
	}
	return rows
}

func assertSigningRowsUseKey(t *testing.T, db *rhiza.DB, keyring *Keyring, issuer, want string) {
	t.Helper()
	rows := signingEnvelopeRows(t, db)
	for kid, encoded := range rows {
		envelope, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("row %q envelope encoding: %v", kid, err)
		}
		got, err := keyring.SigningKeyEnvelopeKeyID(issuer, kid, envelope)
		if err != nil || got != want {
			t.Fatalf("row %q key ID=%q err=%v", kid, got, err)
		}
	}
}

package oidc

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestManagedClientSecretPurposeBoundsAndBinding(t *testing.T) {
	t.Parallel()
	keyring := fixedKeyring("master-a")
	id, generation := strings.Repeat("a", 256), strings.Repeat("g", 32)
	purpose := ManagedClientSecretPurpose(id, generation)
	if len(purpose) > 64 {
		t.Fatalf("purpose exceeds envelope boundary: %d", len(purpose))
	}
	envelope, err := keyring.SealEnvelope(purpose, []byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := keyring.OpenEnvelope(purpose, envelope)
	if err != nil || string(plain) != "test-secret" {
		t.Fatalf("round trip failed: %v", err)
	}
	for _, other := range []string{ManagedClientSecretPurpose(id+"b", generation), ManagedClientSecretPurpose(id, generation+"h")} {
		if _, err := keyring.OpenEnvelope(other, envelope); err == nil {
			t.Fatal("client/generation binding was not authenticated")
		}
	}
	if ManagedClientSecretPurpose("ab", "c") == ManagedClientSecretPurpose("a", "bc") {
		t.Fatal("ambiguous ID/generation concatenation")
	}
}

func insertManagedEnvelope(t *testing.T, db *rhiza.DB, id, generation string, envelope []byte) {
	t.Helper()
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "managed-test-" + id, SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,metadata_json,secret_envelope) VALUES(?,?,1,1,'{}',?)`, Args: []any{id, generation, envelope}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedClientEnvelopeReferencesBlockOldKeyAndTamperFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	old, active := fixedKeyring("master-a"), fixedKeyring("master-b")
	envelope, err := old.SealEnvelope(ManagedClientSecretPurpose("client-a", "generation-1"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	insertManagedEnvelope(t, db, "client-a", "generation-1", envelope)
	status, err := InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", nowForTest())
	if err != nil || status.Safe || status.ManagedClients.ByKeyID["master-a"] != 1 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "managed-tamper", SQL: `UPDATE managed_oauth_clients SET secret_envelope=? WHERE id=?`, Args: []any{[]byte{1, 2, 3}, "client-a"}})
	if err != nil {
		t.Fatal(err)
	}
	status, err = InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", nowForTest())
	if !errors.Is(err, ErrUnsafeMasterKeyStatus) || status.Safe {
		t.Fatalf("tampered status=%+v err=%v", status, err)
	}
}

func TestRewrapManagedClientSecretBatchPreservesPlaintextAndUsesCAS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	old, active := fixedKeyring("master-a"), fixedKeyring("master-b")
	purpose := ManagedClientSecretPurpose("client-b", "generation-2")
	envelope, err := old.SealEnvelope(purpose, []byte("secret-b"))
	if err != nil {
		t.Fatal(err)
	}
	insertManagedEnvelope(t, db, "client-b", "generation-2", envelope)
	result, err := RewrapManagedClientSecretBatch(ctx, db, active, "")
	if err != nil || result.Rewrapped != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT generation,revision,secret_envelope FROM managed_oauth_clients WHERE id=?`, Args: []any{"client-b"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 1 || rows.Rows[0][0] != "generation-2" || rows.Rows[0][1] != int64(1) {
		t.Fatalf("row=%v", rows.Rows)
	}
	newEnvelope, ok := rows.Rows[0][2].([]byte)
	if !ok {
		t.Fatalf("envelope type=%T", rows.Rows[0][2])
	}
	plain, err := active.OpenEnvelope(purpose, newEnvelope)
	if err != nil || !bytes.Equal(plain, []byte("secret-b")) {
		t.Fatalf("plaintext=%q err=%v", plain, err)
	}
}

func nowForTest() time.Time { return time.Unix(1_900_000_000, 0).UTC() }

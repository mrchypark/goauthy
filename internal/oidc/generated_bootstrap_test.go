package oidc

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func insertGeneratedAPIKeyBootstrapEnvelope(t *testing.T, db *rhiza.DB, keyring *Keyring, payload []byte) []byte {
	t.Helper()
	envelope, err := keyring.SealEnvelope(GeneratedAPIKeyBootstrapEnvelopePurpose, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "generated-api-key-bootstrap-test-insert", SQL: `INSERT INTO generated_api_key_bootstrap(singleton,config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms) VALUES(1,?,?,?,?)`, Args: []any{"config-digest", envelope, int64(1), int64(2)}}); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func generatedAPIKeyBootstrapEnvelope(t *testing.T, db *rhiza.DB) []byte {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT payload_envelope FROM generated_api_key_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("rows=%v err=%v", rows.Rows, err)
	}
	if rows.Rows[0][0] == nil {
		return nil
	}
	envelope, ok := rows.Rows[0][0].([]byte)
	if !ok {
		t.Fatalf("envelope type=%T", rows.Rows[0][0])
	}
	return envelope
}

func TestGeneratedAPIKeyBootstrapEnvelopeReferencesAndRewrap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	old, active := fixedKeyring("master-a"), fixedKeyring("master-b")
	payload := []byte(`{"version":1,"deadline":1,"entries":[]}`)
	oldEnvelope := insertGeneratedAPIKeyBootstrapEnvelope(t, db, old, payload)

	status, err := InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", nowForTest().Add(48*time.Hour))
	if err != nil || status.Safe || status.GeneratedAPIKeyBootstrap.Total != 1 || status.GeneratedAPIKeyBootstrap.ByKeyID["master-a"] != 1 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	result, err := RewrapGeneratedAPIKeyBootstrapEnvelope(ctx, db, active)
	if err != nil || result.Rewrapped != 1 || !result.Done {
		t.Fatalf("rewrap=%+v err=%v", result, err)
	}
	newEnvelope := generatedAPIKeyBootstrapEnvelope(t, db)
	if bytes.Equal(oldEnvelope, newEnvelope) {
		t.Fatal("old envelope remained")
	}
	plain, err := active.OpenEnvelope(GeneratedAPIKeyBootstrapEnvelopePurpose, newEnvelope)
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("plain=%q err=%v", plain, err)
	}
	status, err = InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", nowForTest())
	if err != nil || !status.Safe || status.GeneratedAPIKeyBootstrap.ByKeyID["master-b"] != 1 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestGeneratedAPIKeyBootstrapEnvelopeTamperAndFenceFailClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("tamper", func(t *testing.T) {
		t.Parallel()
		db := testDB(t)
		active := fixedKeyring("master-b")
		insertGeneratedAPIKeyBootstrapEnvelope(t, db, active, []byte(`{"version":1,"deadline":0,"entries":[]}`))
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "generated-api-key-bootstrap-test-tamper", SQL: `UPDATE generated_api_key_bootstrap SET payload_envelope=? WHERE singleton=1`, Args: []any{[]byte{1, 2, 3}}}); err != nil {
			t.Fatal(err)
		}
		status, err := InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", nowForTest())
		if !errors.Is(err, ErrUnsafeMasterKeyStatus) || status.Safe {
			t.Fatalf("status=%+v err=%v", status, err)
		}
	})
	t.Run("fenced rewrap preserves ciphertext", func(t *testing.T) {
		t.Parallel()
		db := testDB(t)
		source, old, replacement := fixedKeyring("master-a"), fixedKeyring("master-a"), fixedKeyring("master-b")
		var sourceKey [32]byte
		for i := range sourceKey {
			sourceKey[i] = byte(i + 65)
		}
		source.active, source.keys["master-c"] = "master-c", sourceKey
		old.keys["master-c"], replacement.keys["master-c"] = sourceKey, sourceKey
		before := insertGeneratedAPIKeyBootstrapEnvelope(t, db, source, []byte(`{"version":1,"deadline":0,"entries":[]}`))
		fenceOIDCWriter(t, db, "master-a", "master-b", nowForTest())
		if _, err := RewrapGeneratedAPIKeyBootstrapEnvelope(ctx, db, old); err == nil {
			t.Fatal("fenced old key rewrapped")
		}
		if after := generatedAPIKeyBootstrapEnvelope(t, db); !bytes.Equal(before, after) {
			t.Fatal("fenced rewrap changed ciphertext")
		}
		if result, err := RewrapGeneratedAPIKeyBootstrapEnvelope(ctx, db, replacement); err != nil || result.Rewrapped != 1 {
			t.Fatalf("replacement rewrap=%+v err=%v", result, err)
		}
	})
}

func TestGeneratedAPIKeyBootstrapRewrapDoesNotReviveExpiryTombstone(t *testing.T) {
	t.Parallel()
	db := testDB(t)
	active := fixedKeyring("master-b")
	insertGeneratedAPIKeyBootstrapEnvelope(t, db, fixedKeyring("master-a"), []byte(`{"version":1,"deadline":0,"entries":[]}`))
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "generated-api-key-bootstrap-test-expire", SQL: `UPDATE generated_api_key_bootstrap SET payload_envelope=NULL WHERE singleton=1`}); err != nil {
		t.Fatal(err)
	}
	result, err := RewrapGeneratedAPIKeyBootstrapEnvelope(context.Background(), db, active)
	if err != nil || result.Rewrapped != 0 || !result.Done || generatedAPIKeyBootstrapEnvelope(t, db) != nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

package apikey

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestSharedGeneratedBootstrapSurvivesCloseOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	config := rhiza.Config{
		NodeID: "shared-generated-restart", DataDir: t.TempDir(),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: t.TempDir(),
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	}
	open := func() *rhiza.DB {
		t.Helper()
		db, err := rhiza.Open(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Migrate(ctx, db); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		return db
	}

	now := time.Unix(2_100_000_000, 0).UTC()
	deadline := now.Add(time.Hour)
	bootstrap, keyDir, artifact := generatedBootstrapFiles(t, "runner", deadline)
	keyring, err := oidc.LoadKeyring(keyDir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}

	db := open()
	store, err := NewStore(db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, bootstrap, keyDir, artifact, keyring, deadline); err != nil {
		_ = db.Close()
		t.Fatalf("initial shared bootstrap: %v", err)
	}
	entries, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", now)
	if err != nil || len(entries) != 1 {
		_ = db.Close()
		t.Fatalf("read initial artifact entry count=%d err=%v", len(entries), err)
	}
	winner := entries[0].Value
	if _, err := store.Authenticate(ctx, "API-Key "+winner); err != nil {
		_ = db.Close()
		t.Fatalf("initial shared winner does not authenticate: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// A new pod may have no local export. Its re-export must use the persisted
	// winner and deadline rather than minting a new Generate secret.
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	db = open()
	store, err = NewStore(db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	restartedNow := now.Add(10 * time.Minute)
	store.now = func() time.Time { return restartedNow }
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, bootstrap, keyDir, artifact, keyring, deadline.Add(24*time.Hour)); err != nil {
		_ = db.Close()
		t.Fatalf("re-export persisted shared winner: %v", err)
	}
	recovered, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", restartedNow)
	if err != nil || len(recovered) != 1 || recovered[0].Value != winner {
		_ = db.Close()
		t.Fatalf("re-export winner entry count=%d matches=%t err=%v", len(recovered), len(recovered) == 1 && recovered[0].Value == winner, err)
	}
	if _, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", deadline); !errors.Is(err, ErrGeneratedBootstrapExpired) {
		_ = db.Close()
		t.Fatalf("re-export extended original deadline: %v", err)
	}
	if _, err := store.Authenticate(ctx, "API-Key "+winner); err != nil {
		_ = db.Close()
		t.Fatalf("reopened shared winner does not authenticate: %v", err)
	}

	store.now = func() time.Time { return deadline }
	if err := store.PurgeSharedGeneratedSecrets(ctx, keyring); err != nil {
		_ = db.Close()
		t.Fatalf("purge expired shared winner: %v", err)
	}
	if err := os.Remove(artifact); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = open()
	defer db.Close()
	store, err = NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return deadline.Add(time.Minute) }
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, bootstrap, keyDir, artifact, keyring, deadline.Add(48*time.Hour)); err != nil {
		t.Fatalf("tombstoned shared bootstrap regenerated: %v", err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT payload_envelope FROM generated_api_key_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != nil {
		t.Fatalf("reopened tombstone row count=%d err=%v", len(row.Rows), err)
	}
	if _, err := os.Stat(artifact); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tombstoned restart re-exported artifact: %v", err)
	}
	if _, err := store.Authenticate(ctx, "API-Key "+winner); err != nil {
		t.Fatalf("original key changed after tombstoned restart: %v", err)
	}
	assertBootstrapCount(t, db, 1)
}

package apikey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestBootstrapWithSharedGeneratedSecretsConvergesAndTombstones(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_100_000_000, 0).UTC()
	deadline := now.Add(time.Hour)
	db := bootstrapTestDB(t, "shared-generated-bootstrap")

	type caller struct {
		store    *Store
		config   string
		keyDir   string
		artifact string
		keyring  *oidc.Keyring
	}
	callers := make([]caller, 3)
	for i := range callers {
		config, keyDir, artifact := generatedBootstrapFiles(t, "runner", deadline)
		keyring, err := oidc.LoadKeyring(keyDir, "dev-1")
		if err != nil {
			t.Fatal(err)
		}
		store, err := NewStore(db)
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return now }
		callers[i] = caller{store: store, config: config, keyDir: keyDir, artifact: artifact, keyring: keyring}
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(callers))
	for i := range callers {
		c := callers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- c.store.BootstrapWithSharedGeneratedSecrets(ctx, c.config, c.keyDir, c.artifact, c.keyring, deadline)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent shared bootstrap: %v", err)
		}
	}

	var winner []BootstrapSecretEntry
	for _, c := range callers {
		entries, err := ReadGeneratedBootstrapSecrets(c.artifact, c.keyDir, "dev-1", now)
		if err != nil || len(entries) != 1 {
			t.Fatalf("read caller artifact count=%d err=%v", len(entries), err)
		}
		if winner == nil {
			winner = entries
		} else if !sameGeneratedBootstrapEntries(winner, entries) {
			t.Fatal("different shared Generate values")
		}
	}
	if _, err := callers[0].store.Authenticate(ctx, "API-Key "+winner[0].Value); err != nil {
		t.Fatalf("shared winner does not authenticate: %v", err)
	}
	assertBootstrapCount(t, db, 1)

	// A valid local artifact which is not the shared winner is never replaced.
	conflictRoot := t.TempDir()
	conflictArtifact := filepath.Join(conflictRoot, "generated.secrets")
	if err := WriteGeneratedBootstrapSecrets(conflictArtifact, callers[0].keyDir, "dev-1", []BootstrapSecretEntry{{Kind: "api-key", ID: "runner", Field: "token", Value: "runner$" + bootstrapTestSecret}}, deadline); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(conflictArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := callers[0].store.BootstrapWithSharedGeneratedSecrets(ctx, callers[0].config, callers[0].keyDir, conflictArtifact, callers[0].keyring, deadline); err == nil {
		t.Fatal("conflicting local artifact accepted")
	}
	after, err := os.ReadFile(conflictArtifact)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("conflicting local artifact overwritten or unreadable: %v", err)
	}

	// The raw config bytes are the explicit shared configuration identity.
	changed := filepath.Join(t.TempDir(), "bootstrap.json")
	content, err := os.ReadFile(callers[0].config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changed, append([]byte("\n"), content...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := callers[0].store.BootstrapWithSharedGeneratedSecrets(ctx, changed, callers[0].keyDir, callers[0].artifact, callers[0].keyring, deadline); err == nil {
		t.Fatal("raw configuration conflict accepted")
	}

	callers[0].store.now = func() time.Time { return deadline }
	if err := callers[0].store.PurgeSharedGeneratedSecrets(ctx, callers[0].keyring); err != nil {
		t.Fatalf("purge expired shared bootstrap: %v", err)
	}
	if err := callers[0].store.BootstrapWithSharedGeneratedSecrets(ctx, callers[0].config, callers[0].keyDir, callers[0].artifact, callers[0].keyring, deadline.Add(time.Hour)); err != nil {
		t.Fatalf("tombstoned bootstrap regenerated: %v", err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT payload_envelope FROM generated_api_key_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != nil {
		t.Fatalf("shared bootstrap tombstone=%#v err=%v", row.Rows, err)
	}
	assertBootstrapCount(t, db, 1)
}

func TestBootstrapWithSharedGeneratedSecretsRejectsExpiredPrewrittenArtifactWithoutRows(t *testing.T) {
	now := time.Unix(2_100_000_000, 0).UTC()
	config, keyDir, artifact := generatedBootstrapFiles(t, "runner", now.Add(time.Hour))
	if err := WriteGeneratedBootstrapSecrets(artifact, keyDir, "dev-1", []BootstrapSecretEntry{{Kind: "api-key", ID: "runner", Field: "token", Value: "runner$" + bootstrapTestSecret}}, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	db := bootstrapTestDB(t, "shared-generated-expired")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.BootstrapWithSharedGeneratedSecrets(context.Background(), config, keyDir, artifact, keyring, now.Add(time.Hour)); err == nil {
		t.Fatal("expired prewritten artifact accepted")
	}
	assertBootstrapCount(t, db, 0)
	row, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM generated_api_key_bootstrap`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(0) {
		t.Fatalf("expired artifact created shared row=%#v err=%v", row.Rows, err)
	}
}

func TestSharedGeneratedBootstrapDoesNotExportBeforeAckDurability(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	db, err := rhiza.Open(ctx, rhiza.Config{
		NodeID: "shared-generated-before-ack", DataDir: t.TempDir(),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: storeDir,
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_100_000_000, 0).UTC()
	config, keyDir, winnerArtifact := generatedBootstrapFiles(t, "runner", now.Add(time.Hour))
	keyring, err := oidc.LoadKeyring(keyDir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, config, keyDir, winnerArtifact, keyring, now.Add(time.Hour)); err != nil {
		t.Fatalf("create shared winner: %v", err)
	}

	backup := storeDir + "-unavailable"
	if err := os.Rename(storeDir, backup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(storeDir); _ = os.Rename(backup, storeDir) })
	if err := os.WriteFile(storeDir, []byte("unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	loserArtifact := filepath.Join(t.TempDir(), "loser.secrets")
	err = store.BootstrapWithSharedGeneratedSecrets(ctx, config, keyDir, loserArtifact, keyring, now.Add(time.Hour))
	if !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("shared loser acknowledged unavailable durability: %v", err)
	}
	if _, statErr := os.Stat(loserArtifact); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("shared loser exported token before durable ack: %v", statErr)
	}

	// The purge can commit locally before before-ack object durability fails.
	// A following starter must still fence the exact NULL tombstone before it
	// reports initialized success or publishes another artifact.
	store.now = func() time.Time { return now.Add(time.Hour) }
	if err := store.PurgeSharedGeneratedSecrets(ctx, keyring); !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("shared purge acknowledged unavailable durability: %v", err)
	}
	tombstoneArtifact := filepath.Join(t.TempDir(), "tombstone.secrets")
	err = store.BootstrapWithSharedGeneratedSecrets(ctx, config, keyDir, tombstoneArtifact, keyring, now.Add(2*time.Hour))
	if !errors.Is(err, rhiza.ErrCommitUnknown) {
		t.Fatalf("tombstone acknowledged unavailable durability: %v", err)
	}
	if _, statErr := os.Stat(tombstoneArtifact); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("tombstoned bootstrap exported token before durable ack: %v", statErr)
	}
}

func TestSharedBootstrapConfigDigestIsRawContent(t *testing.T) {
	value := []byte(`[{"name":"runner"}]`)
	if sharedBootstrapConfigDigest(value) == sharedBootstrapConfigDigest(append([]byte(" "), value...)) {
		t.Fatal("raw bootstrap configuration digest ignored source bytes")
	}
	if _, err := base64.RawURLEncoding.DecodeString(sharedBootstrapConfigDigest(value)); err != nil {
		t.Fatalf("config digest is not base64url: %v", err)
	}
}

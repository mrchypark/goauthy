package oidc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestOIDCEnvelopeWritersHonorFencedOldKeyAndAllowReplacement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer := "https://id.example.com"
	now := time.Unix(1_800_000_000, 0).UTC()

	t.Run("bootstrap", func(t *testing.T) {
		t.Parallel()
		db := testDB(t)
		fenceOIDCWriter(t, db, "master-a", "master-b", now)
		if _, err := EnsureSigningKey(ctx, db, fixedKeyring("master-a"), issuer, now); err == nil {
			t.Fatal("fenced old bootstrap writer committed")
		}
		assertSigningKeyStates(t, db, 0, 0, 0)
		if _, err := EnsureSigningKey(ctx, db, fixedKeyring("master-b"), issuer, now); err != nil {
			t.Fatalf("replacement bootstrap writer failed: %v", err)
		}
	})

	t.Run("prepare", func(t *testing.T) {
		t.Parallel()
		db := testDB(t)
		old := fixedKeyring("master-a")
		if _, err := EnsureSigningKey(ctx, db, old, issuer, now); err != nil {
			t.Fatal(err)
		}
		fenceOIDCWriter(t, db, "master-a", "master-b", now)
		if _, err := PrepareSigningKey(ctx, db, old, issuer, now); err == nil {
			t.Fatal("fenced old prepare writer committed")
		}
		assertSigningKeyStates(t, db, 1, 0, 0)
		prepared, err := PrepareSigningKey(ctx, db, fixedKeyring("master-b"), issuer, now)
		if err != nil || !prepared.Prepared {
			t.Fatalf("replacement prepare writer result=%#v err=%v", prepared, err)
		}
	})

	t.Run("rewrap", func(t *testing.T) {
		t.Parallel()
		db := testDB(t)
		old := fixedKeyring("master-a")
		if _, err := EnsureSigningKey(ctx, db, old, issuer, now); err != nil {
			t.Fatal(err)
		}
		source := fixedKeyring("master-c")
		var sourceKey [32]byte
		for i := range sourceKey {
			sourceKey[i] = byte(i + 65)
		}
		source.keys["master-c"] = sourceKey
		old.keys["master-c"] = sourceKey
		insertSigningRewrapRow(t, db, source, issuer, bytes.Repeat([]byte{7}, 32), "retiring", now)
		before := signingEnvelopeRows(t, db)
		fenceOIDCWriter(t, db, "master-a", "master-b", now)
		if _, err := RewrapSigningKeyEnvelopeBatch(ctx, db, old, issuer, ""); err == nil {
			t.Fatal("fenced old rewrap writer committed")
		}
		after := signingEnvelopeRows(t, db)
		if len(before) != len(after) {
			t.Fatalf("fenced rewrap changed row count: before=%d after=%d", len(before), len(after))
		}
		for kid, envelope := range before {
			if after[kid] != envelope {
				t.Fatalf("fenced rewrap changed row %q", kid)
			}
		}
		replacement := fixedKeyring("master-b")
		replacement.keys["master-c"] = sourceKey
		if result, err := RewrapSigningKeyEnvelopeBatch(ctx, db, replacement, issuer, ""); err != nil || result.Rewrapped != 2 {
			t.Fatalf("replacement rewrap result=%#v err=%v", result, err)
		}
		assertSigningRowsUseKey(t, db, replacement, issuer, "master-b")
	})
}

func fenceOIDCWriter(t *testing.T, db *rhiza.DB, oldKeyID, replacementKeyID string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{
		Epoch:            1,
		OldKeyID:         oldKeyID,
		ReplacementKeyID: replacementKeyID,
		MemberIDs:        []string{"node-0", "node-1", "node-2"},
		PreparedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
}

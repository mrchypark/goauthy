package identity

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/rhiza"
)

func TestCleanupExpiredOpenRegistrationSCIMBatchLeavesAndThenRemovesRemainder(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, credential.DefaultRules())
	base := time.UnixMilli(2_000_000).UTC()
	store.now = func() time.Time { return base }
	if err := store.ConfigureSCIMTombstoneProviders([]SCIMTombstoneProvider{
		{ID: "provider-a", DeletePolicy: scim.DeleteRemote},
		{ID: "provider-b", DeletePolicy: scim.DeleteRemote},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 65; i++ {
		if _, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "batch-" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + "@example.test", TTL: time.Minute}); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}

	if err := store.CleanupExpiredOpenRegistrations(ctx, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users`, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones`, 64)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstone_providers`, 128)

	remaining, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT subject FROM identity_users`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(remaining.Rows) != 1 || len(remaining.Rows[0]) != 1 {
		t.Fatalf("remaining user rows=%#v err=%v", remaining.Rows, err)
	}
	subject, ok := remaining.Rows[0][0].(string)
	if !ok || subject == "" {
		t.Fatalf("remaining subject=%#v", remaining.Rows)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("remaining user tombstone rows=%#v err=%v", rows.Rows, err)
	}

	if err := store.CleanupExpiredOpenRegistrations(ctx, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM identity_users`, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstones`, 65)
	assertCount(t, store, `SELECT COUNT(*) FROM scim_user_tombstone_providers`, 130)
}
